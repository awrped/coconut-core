#include "javahooks.h"

std::vector<std::string> JavaHooks::classes;
jclass JavaHooks::javaHook_class;

bool JavaHooks::init(JNIEnv *env, jvmtiEnv *jvmti) {
    this->env = env;
    this->jvmti = jvmti;

    jclass hookClass = env->FindClass("dev/coconut/javahooks/JavaHooks");
    if (hookClass == nullptr) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    this->javaHook_class = (jclass) env->NewGlobalRef(hookClass);

    jvmtiCapabilities caps{};
    caps.can_retransform_classes = 1;
    caps.can_retransform_any_class = 1;

    if (jvmti->AddCapabilities(&caps) != JVMTI_ERROR_NONE)
        return false;

    jvmtiEventCallbacks callbacks{};
    callbacks.ClassFileLoadHook = ClassFileLoadHook;

    if (jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks)) != JVMTI_ERROR_NONE)
        return false;

    if (jvmti->SetEventNotificationMode(
            JVMTI_ENABLE,
            JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,
            nullptr) != JVMTI_ERROR_NONE)
        return false;

    return true;
}

void JavaHooks::register_hook_callback(const char *clazz, const char *method, const char *sig, void *callback) {
    JNINativeMethod methods[] = {
        {
            const_cast<char *>(method),
            const_cast<char *>(sig),
            callback
        }
    };

    jclass c = env->FindClass(clazz);
    if (c == nullptr) {
        printf("[javahooks] could not find class: %s\n", clazz);
        return;
    }
    if (env->RegisterNatives(c, methods, 1) != 0) {
        printf("[javahooks] could not register native for: %s.%s", clazz, method);
        return;
    }

    printf("[javahooks] registered native for %s\n", clazz);
}

bool JavaHooks::retransform(const char *name) {
    printf("retransform %s\n", name);
    classes.emplace_back(name);
    jint classCount = 0;
    jclass *loadedClasses = nullptr;

    if (jvmti->GetLoadedClasses(&classCount, &loadedClasses) != JVMTI_ERROR_NONE) {
        return false;
    }

    std::string targetSignature = "L" + std::string(name) + ";";

    jclass target = nullptr;

    for (jint i = 0; i < classCount; i++) {
        char *signature = nullptr;

        if (jvmti->GetClassSignature(loadedClasses[i], &signature, nullptr) == JVMTI_ERROR_NONE && signature) {
            if (targetSignature == signature) {
                target = loadedClasses[i];
                jvmti->Deallocate(reinterpret_cast<unsigned char *>(signature));
                break;
            }
            jvmti->Deallocate(reinterpret_cast<unsigned char *>(signature));
        }
    }

    jvmti->Deallocate(reinterpret_cast<unsigned char *>(loadedClasses));
    return jvmti->RetransformClasses(1, &target) == JVMTI_ERROR_NONE;
}

thread_local bool inHook = false;

void JNICALL JavaHooks::ClassFileLoadHook(
    jvmtiEnv *jvmti,
    JNIEnv *env,
    jclass class_being_redefined,
    jobject loader,
    const char *name,
    jobject protection_domain,
    jint class_data_len,
    const unsigned char *class_data,
    jint *new_class_data_len,
    unsigned char **new_class_data
) {
    if (name == nullptr)
        return;

    if (inHook)
        return;

    inHook = true;

    jmethodID processMethod = env->GetStaticMethodID(javaHook_class, "process", "(Ljava/lang/String;[B)[B");
    if (processMethod == nullptr) {
        printf("JavaHooks.process is null");
        inHook = false;
        return;
    }

    jbyteArray input = env->NewByteArray(class_data_len);
    env->SetByteArrayRegion(input, 0, class_data_len, (jbyte *) class_data);
    jstring str = env->NewStringUTF(name);

    jbyteArray output = (jbyteArray) env->CallStaticObjectMethod(javaHook_class, processMethod, str, input);
    if (std::ranges::find(classes, name) != classes.end()) {
        printf("[javahooks] hooked %s\n", name);

        if (!output) {
            goto cleanup;
        }

        jint length = env->GetArrayLength(output);
        if (length <= 0) {
            goto cleanup;
        }

        unsigned char *transformedClassData = nullptr;

        if (jvmti->Allocate(length, &transformedClassData) != JVMTI_ERROR_NONE || !transformedClassData) {
            goto cleanup;
        }

        env->GetByteArrayRegion(output, 0, length, reinterpret_cast<jbyte *>(transformedClassData));

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            jvmti->Deallocate(transformedClassData);
            goto cleanup;
        }

        *new_class_data_len = length;
        *new_class_data = transformedClassData;
    }

cleanup:
    if (output) env->DeleteLocalRef(output);
    env->DeleteLocalRef(input);
    env->DeleteLocalRef(str);

    inHook = false;
}
