#pragma once
#ifndef URL_CLASSLOADER_HOOK
#define URL_CLASSLOADER_HOOK

#include <cctype>
#include <cstdio>
#include <string>
#include "windows.h"

namespace Hooks {
    jobject JNICALL urlClassLoaderHook(JNIEnv *env, jclass clazz, jobject loader, jobject urlObj) {
        printf("[java/net/URLClassLoader] addURL(URL) called\n");
        if (urlObj == nullptr) {
            printf("[hook] url is null\n");
            return nullptr;
        }

        jclass urlClass = env->FindClass("java/net/URL");
        jmethodID getProtocol = env->GetMethodID(urlClass, "getProtocol", "()Ljava/lang/String;");
        jmethodID toExternalForm = env->GetMethodID(urlClass, "toExternalForm", "()Ljava/lang/String;");

        jstring protocolJava = static_cast<jstring>(env->CallObjectMethod(urlObj, getProtocol));
        jstring externalJava = static_cast<jstring>(env->CallObjectMethod(urlObj, toExternalForm));
        const char *protocolChars = protocolJava ? env->GetStringUTFChars(protocolJava, nullptr) : nullptr;
        const char *externalChars = externalJava ? env->GetStringUTFChars(externalJava, nullptr) : nullptr;

        std::string protocol = protocolChars ? protocolChars : "";
        std::string external = externalChars ? externalChars : "";
        for (char &ch: protocol) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }

        printf("url: %s\n", external.c_str());
        printf("protocol: %s\n", protocol.c_str());
        env->DeleteLocalRef(urlClass);

        jclass hookStatus = env->FindClass("dev/coconut/javahooks/HookStatus");
        if (protocol == "http" || protocol == "https" || protocol == "ftp" ||
            (protocol == "jar" && (
                 external.rfind("jar:http://", 0) == 0 ||
                 external.rfind("jar:https://", 0) == 0 ||
                 external.rfind("jar:ftp://", 0) == 0
             ))) {
            MessageBoxA(NULL, external.c_str(), "URLClassLoader.addURL blocked", MB_OK);

            jfieldID cancelField = env->GetStaticFieldID(
                hookStatus,
                "CANCEL",
                "Ldev/coconut/javahooks/HookStatus;"
            );
            jobject cancelValue = env->GetStaticObjectField(hookStatus, cancelField);
            env->DeleteLocalRef(hookStatus);
            return cancelValue;
        }

        jfieldID passField = env->GetStaticFieldID(
            hookStatus,
            "PASS",
            "Ldev/coconut/javahooks/HookStatus;"
        );
        jobject passValue = env->GetStaticObjectField(hookStatus, passField);
        env->DeleteLocalRef(hookStatus);
        return passValue;
    }
}

#endif
