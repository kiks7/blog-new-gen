---
title: Android Internals Deep Dive - Implicit Intents
date: 2025-02-14
author: kiks
---
## Introduction
From the official [Android documentation](https://developer.android.com/reference/android/content/Intent), the `Intent` is described as “an abstract description of an operation to be performed”. Conceptually, it can be simplified as an “intention to do something with another application” across Inter-Process Communication (IPC). One of the most interesting facility that intents offer is the implicit resolution. An application can explicitly declare to handle specific intents (through the `<intent-filter>` declaration) and these intents are ***magically*** delivered to it from other applications, without the knowledge of the final destination package. Since magic can be hypothetically just defined as a form of ignorance (*at least* in computer science?), let’s see where the “magic” happens in the Android source code!

## Intent registration
### Starting from the beginning
Let's start from an application point of view that needs to handle specific actions: an `<intent-filter>` is declared inside the `AndroidManifest.xml`:
```xml
<component android:name>
	<intent-filter>
		<action android:name="android.intent.action.VIEW">
		<category android:name="android.intent.category.DEFAULT"/>
		<data android:scheme="scheme"/>
	</intent-filter>
</component>
```
In this example, the `component` can be of any type: an `activity`, `receiver`, `service` or `provider`. Some filters are also specified in order to discriminate matching events that the component is interested into: `action`, `category` and `data` (with the `android:scheme` attribute) are specifically used in this case (check out the [\<intent-filter\> documentation](https://developer.android.com/guide/topics/manifest/intent-filter-element) for more filters and options).
At install time, the [`PackageInstaller`](https://developer.android.com/reference/android/content/pm/PackageInstaller) service is responsible to install the application and all its components, including intent filters. More specifically, diving into the AOSP (Android Open Source Project) codebase, it is possible to identify some key functions that parse all declared components. More specifically, the [`ComponentResolver::addAllComponents`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/pm/resolution/ComponentResolver.java;drc=4bf59a583eefeb8b27a79fbd1fc5093ddb79d747;l=191) method calls four methods that parse all components' details.

```java 
    public void addAllComponents(/*..*/){
        /*..*/
        synchronized (mLock) {
            addActivitiesLocked(computer, pkg, newIntents, chatty);
            addReceiversLocked(computer, pkg, chatty);
            addProvidersLocked(computer, pkg, chatty);
            addServicesLocked(computer, pkg, chatty);
            onChanged();
        }
        /*..*/
```

Following the `Add[Component]Locked` logic, components are registered based on their type on specific variables (e.g. `mActivities`, `mProviders`, `mReceivers` and `mServices`) and then intent filters are parsed. Let's take the activity parsing as an example to reference some code, but the concept is the same across all different components. `addActivitiesLocked` calls [`mActivities.addActivity`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/pm/resolution/ComponentResolver.java;l=282) (part of the `ComponentResolver` class) that calls `addFilter` for each declared intent filter.

```java
	// code cutted for demonstration purposes
	protected void addActivity(@NonNull Computer computer, ParsedActivity a, String type,
			List<Pair<ParsedActivity, ParsedIntentInfo>> newIntents) {
		final int intentsSize = a.getIntents().size();
		for (int j = 0; j < intentsSize; j++) {
			ParsedIntentInfo intent = a.getIntents().get(j);
			IntentFilter intentFilter = intent.getIntentFilter();
			if (newIntents != null && "activity".equals(type)) {
				newIntents.add(Pair.create(a, intent));
			}
			/* .. */
			addFilter(computer, Pair.create(a, intent));
		}
	}
```

Intents are cycled within a for loop and each declared intent filter is passed as an argument to [`ComponentResolver::MimeGroupsAwareIntentResolver::addFilter`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/pm/resolution/ComponentResolver.java;l=834) that finally calls [`IntentResolver::addFilter`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/IntentResolver.java;l=58) where most of the registering process happens. Before diving into the logic of this specific method, it is important to discriminate intent filters as they are internally classified: `Full MIME Types`, `Base MIME Types`, `Wild MIME Types`, `Schemes`, `Non-data Actions`, `MIME Typed Actions`.
### The "obscure", less-known, internal classification
The "obscure" adjective is a clearly amplification of the concept, but there is an interesting internal intent classification (that influences the consecutive resolution process) that is not explicitly documented in the Android Documentation (that is, for most parts, really complete) and it was possible to identify it by wandering in the codebase, more specifically into the [`IntentResolver::dump`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/IntentResolver.java;l=286) method reachable from the `dumpsys` utility (more on that later). These categories are not really difficult to understand and they are particularly influenced by the specified MIME type that can be explicitly defined in the `<intent-filter>` declaration using the [`mimeType`](https://developer.android.com/guide/topics/manifest/data-element#mime) attribute inside the [`<data>`](https://developer.android.com/guide/topics/manifest/data-element) tag . The MIME type standard is widely used across technologies in order to identify resource types (e.g. `image/png`, `text/html`, ..) and consists of two main parts that we are interested into:
- **Type**: the generic type of the the format, for example `image`, `application`, `audio`, `video` and so on.
- **Subtype**: the subtype is more specific and contains the media format. For example `png`, `html` and `mp4` are an example of possible subtypes. 

With this knowledge, we can go through all categories:
- `Full MIME Types`: inside this category we have all possible MIME Types independently of its two parts (e.g. `image/png` and `image/*`).
- `Base MIME Types`: the base classification is related to data types that fully contains the two parts (e.g. `image/png` or `video/mp4`).
- `Wild MIME Types`: MIME Types without the "subtype" (e.g. `image` or `video`) or with a mask (e.g. `image/*` or `video/*`).
- `Schemes`: intent filters that handles data schemes (e.g. `<data android:scheme="scheme"/>`).
- `Non-data Actions`: Intent filters that do not contain any MIME type and data scheme.
- `MIME Typed Actions`: Intent filters that contains at least one MIME type.

As can be seen, an intent filter can also fall inside different categories. For example, an intent filter declared with a `mimeType` of value `image` is classified inside the `Full MIME Type` (as it contains a MIME type), `Wild Mime Type`  (as it contains only the first part of the MIME type) and `MIME Typed Action` since it contains at least one MIME type.

### Registering methods
After this needed digression on the internal classification, let's jump back to the [`IntentResolver::addFilter`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/IntentResolver.java;l=58):

```java
// simplified code
public void addFilter(@Nullable PackageDataSnapshot snapshot, F f) {
	/* .. */*
	mFilters.add(f);
	int numS = register_intent_filter(f, intentFilter.schemesIterator(),
			mSchemeToFilter, "      Scheme: ");
	int numT = register_mime_types(f, "      Type: ");
	if (numS == 0 && numT == 0) {
		register_intent_filter(f, intentFilter.actionsIterator(),
				mActionToFilter, "      Action: ");
	}
	if (numT != 0) {
		register_intent_filter(f, intentFilter.actionsIterator(),
				mTypedActionToFilter, "      TypedAction: ");
	}
}

private final int register_mime_types(F filter, String prefix) {
	final Iterator<String> i = getIntentFilter(filter).typesIterator();
	/* .. */
	int num = 0;
	while (i.hasNext()) {
		String name = i.next();
		num++;
		String baseName = name;
		final int slashpos = name.indexOf('/');
		if (slashpos > 0) {
			baseName = name.substring(0, slashpos).intern();
		} else {
			name = name + "/*";
		}

		addFilter(mTypeToFilter, name, filter);

		if (slashpos > 0) {
			addFilter(mBaseTypeToFilter, baseName, filter);
		} else {
			addFilter(mWildTypeToFilter, baseName, filter);
		}
	}
	return num;
}
```

This method is responsible to register three main categories through its code using the [`IntentResolver::register_intent_filter`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/IntentResolver.java;l=640) method: `Schemes`, `Non-Data actions` and `Typed`, while other MIME-related categories are registered through [`IntentResolver::register_mime_types`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/IntentResolver.java;l=579). As can be observed from the code, filters are registered following the previously described classification and results are stored inside the following class members (defined inside [`IntentResolver.java`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/IntentResolver.java;l=871)): `mSchemeToFilter`, `mActionToFilter`, `mTypedActionToFilter`, `mTypedActionToFilter`, `mBaseTypeToFilter` and `mWildTypeToFilter`. These members are later used for the resolution process.
## Intent resolution
We have seen the logic behind the registration process of intent filters and now we are in the hearth of the topic: the resolution process.
The resolution process, and related system services and APIs, particularly depends on the targeted components (activities, receivers, services or providers) but in order to circumscribe the logic, let's take into account two common APIs: `startActivity` and `sendBroadcast`. They can both send intents and, more importantly, **implicit** intents. 
### startActivity
Let's start our journey with the `startActivity` API, using a simple code as a reference:
```java
Intent in = new Intent("com.example.non_existent.ACTION", Uri.parse("13371337"););
startActivity(in);
```

From the imported library code (e.g. inside the sender application process) after some preliminary error checking, the `startActivity` method from the `ActivityTaskManager` system service is called. This service method is responsible to find and start the destination activity if matched and it is part of the `system_server` services. In order to find target destinations that match a specific intent action (if not explicitly set from the sender), the previously described attributes (`mSchemeToFilter`, `mActionToFilter`, ..) are consulted from an internal method: [`IntentResolver::queryIntent`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/IntentResolver.java;l=382). 
#### IntentResolver::queryIntent
This method is reached after multiple calls (see the [[#Backtrace startActivity]] backtrace for all involved methods) and is responsible to loop over mentioned attributes in order to find most suitable destinations. The returned result is a list of candidates (`List<R>`).
The objective is not as easy to implement: a requested intent can have multiple candidates of any type (matching the MIME type, scheme and data) but need to return results that include everything!
```java
protected final List<R> queryIntent(@NonNull PackageDataSnapshot snapshot, Intent intent,
		String resolvedType, boolean defaultOnly, @UserIdInt int userId, long customFlags) {
	String scheme = intent.getScheme();
	ArrayList<R> finalList = new ArrayList<R>();
	/* .. */

	F[] firstTypeCut = null;
	F[] secondTypeCut = null;
	F[] thirdTypeCut = null;
	F[] schemeCut = null;

	// If the intent includes a MIME type, then we want to collect all of
	// the filters that match that MIME type.
	if (resolvedType != null) { // [1]
		int slashpos = resolvedType.indexOf('/');
		if (slashpos > 0) {
			final String baseType = resolvedType.substring(0, slashpos);
			if (!baseType.equals("*")) {
				if (resolvedType.length() != slashpos+2
						|| resolvedType.charAt(slashpos+1) != '*') {
					firstTypeCut = mTypeToFilter.get(resolvedType); // [2]
					secondTypeCut = mWildTypeToFilter.get(baseType); // [4]
				} else {
					// We can match anything with our base type.
					firstTypeCut = mBaseTypeToFilter.get(baseType); // [3]
					secondTypeCut = mWildTypeToFilter.get(baseType); // [4]
				}
				thirdTypeCut = mWildTypeToFilter.get("*");
			} else if (intent.getAction() != null) {
				// The intent specified any type ({@literal *}/*).  This
				// can be a whole heck of a lot of things, so as a first
				// cut let's use the action instead.
				firstTypeCut = mTypedActionToFilter.get(intent.getAction()); // [5]
			}
		}
	}

	if (scheme != null) {
		schemeCut = mSchemeToFilter.get(scheme); // [6]
	}

	if (resolvedType == null && scheme == null && intent.getAction() != null) {
		firstTypeCut = mActionToFilter.get(intent.getAction()); // [7]
	}

	FastImmutableArraySet<String> categories = getFastIntentCategories(intent);
	Computer computer = (Computer) snapshot;
	if (firstTypeCut != null) {
		buildResolveList(computer, intent, categories, debug, defaultOnly, resolvedType,
				scheme, firstTypeCut, finalList, userId, customFlags);
	}
	if (secondTypeCut != null) {
		buildResolveList(computer, intent, categories, debug, defaultOnly, resolvedType,
				scheme, secondTypeCut, finalList, userId, customFlags);
	}
	if (thirdTypeCut != null) {
		buildResolveList(computer, intent, categories, debug, defaultOnly, resolvedType,
				scheme, thirdTypeCut, finalList, userId, customFlags);
	}
	if (schemeCut != null) {
		buildResolveList(computer, intent, categories, debug, defaultOnly, resolvedType,
				scheme, schemeCut, finalList, userId, customFlags);
	}
	filterResults(finalList);
	sortResults(finalList);

	/* .. */
	return finalList;
}
```

The `queryIntent` function satisfy this logic by using multiple "cuts". It starts from the first cut that is related to MIME types[1]: if the intent matches some MIME type, the matching candidates are extracted from `Full MIME Types` [2], `Base MIME Types` [3] and `Wild Mime Types` [4] relative members. An interesting behavior is for the `Typed Action` filters[5]: If the primary part of the MIME type is `*` (e.g. `*/*`) then, since the target can be anything and is too much generic, the action is used as a discrimination.
Then, if the `scheme` is specified, `schemes` candidate filters are retrieved [6] and the same (if the `scheme` is null) for the `Non-data actions`[7]. Every cut candidates are then confirmed from the `buildResolveList` to match all requested intent characteristics with the [`intentFilter.match(..)`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/IntentResolver.java;l=773) call
and the final list is returned in the `finalList` variable.

### sendBroadcast
The `senBroadcast` resolution logic is really similar to the `startActivity` function with a major difference: the requested method and service.
```java
Intent in = new Intent("com.example.non_existent.ACTION", Uri.parse("13371337"););
sendBroadcast(in);
```

The involved service is the `ActivityManager` with the `broadcastIntentWithFeature` service method. As can be seen from the stack trace at the bottom ([[#Backtrace sendBroadcast]]) the `IntentResolver::queryIntent` method is called from the `ComponentResolver` class and the logic is the same one describer earlier.
### System Services and other methods
We have treated two common methods but there are multiple entry points to resolve intents for different types of components, however the logic is always the same: registered intents are cycled through the `IntentResolver::queryIntent` method. For example, the `queryIntentActivities` method is another commonly used method, exposed from the `PackageManager` system service, to resolve intents. AIDLs (Android Interface Definition Language) for the described services can be consulted there for more exposed functionalities: [`IActivityTaskManager.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/app/IActivityTaskManager.aidl;l=95;bpv=0;bpt=0?q=IActivityTaskManager&ss=android/platform/superproject/main), [`IActivityManager.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/app/IActivityManager.aidl;l=1;bpv=0;bpt=0?q=android.app.IActivityManager&sq=&ss=android/platform/superproject/main) and [`PackageManager.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/content/pm/IPackageManager.aidl;l=1;bpv=0;bpt=0?q=IPackageManager.aidl%20&ss=android/platform/superproject/main)
## dumpsys
The `dumpsys` utility is extremely helpful to list all registered intent filters in the system through the `package` argument. It offers the internal classification structure as output and the dump logic can be found from the previously mentioned [`IntentResolver::dump`](https://cs.android.com/android/platform/superproject/+/android-14.0.0_r37:frameworks/base/services/core/java/com/android/server/IntentResolver.java;l=286) method. The output contains the "Resolver Table" for each component type (activity, receiver, service and provider) with the described internal classification (`Full MIME Types`, `Non-data actions`, ..). For example, the `adb shell dumpsys package` returns a similar output:
```bash
$ adb shell dumpsys package
# ...
Activity Resolver Table:
  Full MIME Types:
      application/pkix-cert:
        9f5fd74 com.android.certinstaller/.CertInstallerMain
      x-mixmedia/*:
        6f2b72d com.google.android.bluetooth/com.android.bluetooth.opp.BluetoothOppLauncherActivity
      vnd.android.cursor.dir/raw_contact:
        58bbd45 com.google.android.contacts/com.android.contacts.activities.PeopleActivity
        ac07323 com.google.android.contacts/com.android.contacts.activities.CompactContactEditorActivity
        d430587 com.google.android.contacts/com.google.android.apps.contacts.editorlite.ContactsEditorlite
      application/vnd.google-apps.map:
        169295e com.google.android.apps.docs/.app.OpenSafUrlActivity
# ....
```

It is possible to add the `-f` option to print details for all specific filters such as declared actions, categories and data. In order to limit the output to a specific app, the application name can be specified: `adb shell dumpsys package com.target.app`.
```bash
$ adb shell dumpsys package com.target.pp
# ...
  MIME Typed Actions:
      android.intent.action.VIEW:
        9f5fd74 com.android.certinstaller/.CertInstallerMain filter fa0d312
          Action: "android.intent.action.VIEW"
          Category: "android.intent.category.DEFAULT"
          StaticType: "application/x-x509-ca-cert"
          StaticType: "application/x-x509-user-cert"
          StaticType: "application/x-x509-server-cert"
          StaticType: "application/x-pkcs12"
          StaticType: "application/x-pem-file"
          StaticType: "application/pkix-cert"
          StaticType: "application/x-wifi-config"
# ...
```

## Backtraces
### Backtrace: startActivity
```java
at com.android.server.IntentResolver.queryIntent(Native Method)
at com.android.server.pm.resolution.ComponentResolver$ActivityIntentResolver.queryIntent(ComponentResolver.java:985)
at com.android.server.pm.resolution.ComponentResolverBase.queryActivities(ComponentResolverBase.java:130)
at com.android.server.pm.ComputerEngine.queryIntentActivitiesInternalBody(ComputerEngine.java:756)
at com.android.server.pm.ComputerEngine.queryIntentActivitiesInternal(ComputerEngine.java:584)
at com.android.server.pm.ResolveIntentHelper.resolveIntentInternal(ResolveIntentHelper.java:190)
at com.android.server.pm.PackageManagerInternalBase.resolveIntentExported(PackageManagerInternalBase.java:476)
at com.android.server.wm.ActivityTaskSupervisor.resolveIntent(ActivityTaskSupervisor.java:766)
at com.android.server.wm.ActivityStarter$Request.resolveActivity(ActivityStarter.java:568)
at com.android.server.wm.ActivityStarter.execute(ActivityStarter.java:707)
at com.android.server.wm.ActivityTaskManagerService.startActivityAsUser(ActivityTaskManagerService.java:1288)
at com.android.server.wm.ActivityTaskManagerService.startActivityAsUser(ActivityTaskManagerService.java:1239)
at com.android.server.wm.ActivityTaskManagerService.startActivity(ActivityTaskManagerService.java:1214)
at android.app.IActivityTaskManager$Stub.onTransact(IActivityTaskManager.java:929)
at com.android.server.wm.ActivityTaskManagerService.onTransact(ActivityTaskManagerService.java:5511)
at android.os.Binder.execTransactInternal(Binder.java:1339)
at android.os.Binder.execTransact(Binder.java:1275)
```
### Backtrace: sendBroadcast
```java
at com.android.server.IntentResolver.queryIntent(Native Method)
at com.android.server.pm.resolution.ComponentResolver$ActivityIntentResolver.queryIntent(ComponentResolver.java:985)
at com.android.server.pm.resolution.ComponentResolverBase.queryActivities(ComponentResolverBase.java:130)
at com.android.server.pm.ComputerEngine.queryIntentActivitiesInternalBody(ComputerEngine.java:756)
at com.android.server.pm.ComputerEngine.queryIntentActivitiesInternal(ComputerEngine.java:584)
at com.android.server.pm.ComputerEngine.queryIntentActivitiesInternal(ComputerEngine.java:628)
at com.android.server.pm.IPackageManagerBase.queryIntentActivities(IPackageManagerBase.java:1000)
at android.content.pm.IPackageManager$Stub.onTransact(IPackageManager.java:2275)
at com.android.server.pm.PackageManagerService$IPackageManagerImpl.onTransact(PackageManagerService.java:6334)
at android.os.Binder.execTransactInternal(Binder.java:1339)
at android.os.Binder.execTransact(Binder.java:1275)
```

## Conclusion
We have covered the internal intent resolution process that deals with the `<intent-filter>` package declaration, going through involved system services and the internal AOSP codebase. In the next blog post we will cover Deep and App linking in more details due to its strict relation with the the intent declaration and its interesting attack surface.

## References
- https://cs.android.com/
- https://developer.android.com/