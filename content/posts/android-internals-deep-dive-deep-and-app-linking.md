---
title: Android Internals Deep Dive - Deep and App Linking
date: 2025-02-21
author: kiks
---
## Introduction
In the [previous part](android-internals-deep-dive-implicit-intents.html) we have covered some internal parts of the codebase that are involved in the intent registration and resolution process. In this one we are going to deepen Deep and App Link resolutions in the Android Operating System and its remote Attack Surface. Deep and App Links are data components that permit to associate a specific link to a specific app component. In order to further detail their usage across the Android system, let's start with a Deep Link introduction.
## Deep Link
Suppose that you are an app developer and you want to make some of your android app components reachable from an external source (e.g. a browser or another application), and you want a "universal" and standard solution: that's where Deep Links come in place! For example, you can have a link like `privateapp://app/login?username=user` that can be called anywhere (almost) and leads to your application execution logic. Moreover, you have a standard approach that you can use to register an arbitrary schema, host and path and you can also pass and receive parameters like a classic web URL. Deep Links are declared in the `AndroidManifest.xml` application file with an `<intent-filter>` declaration inside the targeted component (that can be an activity, service, receiver or provider). The following declaration can match the previously mentioned example:

```xml
<activity android:name=".TargetLoginActivity">
	<intent-filter>
		<action android:name="android.intent.action.VIEW">
		<category android:name="android.intent.category.DEFAULT"/>
		<category android:name="android.intent.category.BROWSABLE"/>
		<data android:scheme="privateapp"/>
		<data android:host="app"/>
		<data android:path="login"/>
	</intent-filter>
</activity>
```

As can be seen the `android:scheme`, `android:host` and `android:path` attributes (more attributes can be found in the [documentation](https://developer.android.com/guide/topics/manifest/data-element)) of the `<data>` tag are used to register the specific URI to handle. Another common approach is to use a single `<data>` tag, but seems discouraged from the official documentation:
```xml
<activity android:name=".TargetLoginActivity">
	<intent-filter>
		<action android:name="android.intent.action.VIEW">
		<category android:name="android.intent.category.DEFAULT"/>
		<category android:name="android.intent.category.BROWSABLE"/>
		<data android:scheme="privateapp"
			android:host="app"
			android:path="login"/>
	</intent-filter>
</activity>
```

The internal classification, as explained in the previous blog post, is of type `Schemes` but it can also contain some MIME types and fall inside other categorizations too (that can be enumerated with `dumpsys package`).

### Actions and Categories
An important aspect of a Deep Link reachability is the declared actions and categories. Not all deep links are intended to be reachable from anywhere but an interesting behavior is that the link can be dropped "anywhere" (e.g. in a browser inside the `<a>` element) and a click into it will results into an **implicit intent** sent from the browser to the android system, that will take care of the resolution to the appropriate destination (as explained in the first article). For that reason, actions and categories have a fundamental role:
- [`ACTION_VIEW`](https://developer.android.com/reference/android/content/Intent#ACTION_VIEW): The VIEW action is the default action that is sent if a link is clicked from an `<a>` element or a button from web page. It is useful to be specified inside the `intent-filter` declaration if the intention is to reach the link from a simple click.
- [`CATEGORY_BROWSABLE`](https://developer.android.com/reference/android/content/Intent#CATEGORY_BROWSABLE): The `BROWSABLE` category is necessary to reach the intent from a web browser (e.g. chrome). When a browser interacts with the `ActivityManager` system service, it asks for the resolution of the desired deep link by also specifying the required `CATEGORY_BROWSABLE` category in the requested `intent` parameter (the second parameter of the `IntentResolver::queryIntent` method). If the targeted intent filter does not match that category, the resolution fails and never happen.
- [`CATEGORY_DEFAULT`](https://developer.android.com/reference/android/content/Intent#CATEGORY_DEFAULT): The DEFAULT category is necessary to the application to respond to implicit intents, as specified in the [documentation](https://developer.android.com/training/app-links/deep-linking).

While `BROWSABLE` and `DEFAULT` are mandatory for the implicit resolution process, the action is not that strictly necessary. The default `VIEW` action is meant for direct link access (e.g. `privateapp://app/login?username=user` inside an `<a>` element) but it's also possible to use the `intent://` approach.

### `intent://` and `parse_uri`
Browsers with android support (e.g. google chrome) can use a special syntax: `intent://`. This syntax, that can be used in a web page as a normal link, permits to launch android app components (that match the `BROWSABLE` and `DEFAULT` categories) directly from a web browser, just like a simpler direct deep link. The [chrome documentation](https://developer.chrome.com/docs/android/intents) details it and uses the following as an URI template:
```java
intent:  
   HOST/URI-path // Optional host  
   #Intent;  
      package=\[string\];  
      action=\[string\];  
      category=\[string\];  
      component=\[string\];  
      scheme=\[string\];  
   end;
```

For example, the previous `privateapp://app/login?username=user` can be `intent://app/login#Intent;scheme=privateapp;end` and perform the same operation. However, one of the main differences is the required action. While a direct deep link requires the target component to have the `ACTION_VIEW` declared and can only trigger that action, the `intent://` scheme permits to call arbitrary actions based on the `action` parameter. For example, the intent `intent://app/login#Intent;scheme=privateapp;action=android.action.ARBITRARY_ACT;end` launches the same intent but with the action `android.action.ARBITRARY_ACT` instead of the default VIEW one. The logic behind this intent creation from an URI can be found in the [`Intent::parseUri`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/core/java/android/content/Intent.java;l=7921) method and, as can be seen from the source code, it is possible to specify different options like categories, target package name, extras, data and so on.

## App Link
App Links are the same as Deep Links but with a major difference: they are associated with a domain. Instead of the `privateapp://app/login?username=user` we can have `https://mypersonal.website.com/login?username=user` that is entirely the same as a classic URL that can be navigated from a web browser but, if the application is installed and the intent filter registered, it permits to continue the navigation to the mobile application, with a better user experience from a mobile point of view. So, an App Link declaration can looks like this:
```xml
<activity android:name=".TargetLoginActivity">
	<intent-filter autoVerify="true">
		<action android:name="android.intent.action.VIEW">
		<category android:name="android.intent.category.DEFAULT"/>
		<category android:name="android.intent.category.BROWSABLE"/>
		<data android:scheme="https"/>
		<data android:host="mypersonal.website.com"/>
		<data android:path="login"/>
	</intent-filter>
</activity>
```

Similar to the previously described deep link but with one crucial difference: the `android:scheme` is either `http` or `https`. In order to associate a specific application to an arbitrary domain, a verification through the [Digital Asset Links](https://developers.google.com/digital-asset-links) is required. Without this verification, the App Link is not trusted and it is not possible to use it. An `assetlinks.json` must be created for that purpose in the target domain, as well explained in the [Verify Android App Links](https://developer.android.com/training/app-links/verify-android-applinks) documentation. For debugging purposes, it is possible to verify App Links through `adb shell pm set-app-links --package com.app.example 1 all` and verify its validation with `adb shell pm get-app-links com.app.example` (the constant should be `1` to be verified).

## Browser perspective
From a browser perspective (e.g. chrome in this overview), intents delivered through deep and app links are requested to a preliminary call to the IPC method `queryIntentActivities` of the `PackageManager` service. If an intent matches, with all requested attributes and the `BROWSABLE` category, the intent is delivered  using `startActivity` from the `ActivityTaskManager` system service. Since the intent matching is performed with `queryIntentActivities`, resolved components can be only activities.

## Linkify
An interesting android class related to Deep and App Links is [`Linkify`](https://developer.android.com/reference/android/text/util/Linkify): it uses regular expressions to transform a piece of text into clickable links.

```java
textView.setText("Contat us at info@mail.com or call +1234567890");
Linkify.addLinks(textView, Linkify.EMAIL_ADDRESSES | Linkify.PHONE_NUMBERS);
```

The "linkified" version of the provided text will generates two clickable links: the e-mail and the phone number. They are both replaced with the system deep link default handler (e.g. `mailto://` and `tel:` for the phone number) in order to send an implicit intent with that scheme. It is possible, in Android 14, to linkify web urls, e-mail addresses, phone numbers and map addresses. The Linkify code is at [`Linkify.java`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/text/util/Linkify.java;l=99;drc=a78d762ccdbcb1f8f40f2c860caca75ade5d486b) file and represent an interesting behaviour that can be used and abused from third-party apps (e.g. messaging apps).

## Fragment Deeplinks
Fragments are commonly used as portions in the Android UI and can be linked to Deep and App Links also if they cannot be exported as normal components. The process of creating a deep link for a fragment is described in the [Android documentation](https://developer.android.com/guide/navigation/design/deep-link) and the main logic is that a "fragment navigation" resource XML file is created and linked to a specific activity through the `<nav-graph>` element:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.myapplication">
    <application ... >
        <activity name=".MainActivity" ...>
            <nav-graph android:value="res/nav_graph.xml" />
        </activity>
    </application>
</manifest>
```

The `res/nav_graph.xml` contains a Deep Link declaration that is tied to a specific fragment and follows the usual Deep and App link declaration style:
```xml
<fragment android:id="@+id/a"
          android:name="com.example.myapplication.FragmentA"
          tools:layout="@layout/a">
        <deepLink app:uri="www.example.com"
                app:action="android.intent.action.MY_ACTION"
                app:mimeType="type/subtype"/>
</fragment>
```

However, they key part is that the `<deepLink>` element, at build time, is transformed into a classic `<intent-filter>` of the activity that holds the `<nav-graph>` declaration (with the appropriate action and categories). That means that, when the application is compiled, the `<intent-filter>` declaration is the same of a "classic" one.

## Conclusion
In this two part series we have covered intent implicit resolution, deep linking and the browser perspective. While assessing the Attack Surface of an Android mobile application, it is crucial to have a solid understanding of these key internal concepts and components.

## References
- https://developer.android.com/guide/topics/manifest/data-element
- https://developer.android.com/training/app-links/deep-linking
- https://developer.chrome.com/docs/android/intents
- https://developer.android.com/guide/navigation/design/deep-link
