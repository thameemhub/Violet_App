# Add project specific ProGuard rules here.
-keepattributes Signature
-keepattributes *Annotation*

# Retrofit
-dontwarn retrofit2.**
-keep class retrofit2.** { *; }
-keepattributes Exceptions

# Gson
-keep class com.zenithal.violet.data.models.** { *; }

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
