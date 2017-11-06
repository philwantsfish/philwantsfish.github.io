---
layout: post
title: Exploring Java deserialization in GitHub
permalink: "security/java-deserialization-github"
excerpt: "Java deserialization vulnerabilities have become easy to exploit and allow an attacker to remotely compromise a server. How prevalent are these vulnerabilities in open-source projects? This post explores how often Java projects use serialization and walks through exploiting a 0-day vulnerability in Gradle."
categories: Deserialization 
tags:
  - Deserialization
---

The [ysoserial](https://github.com/frohoff/ysoserial) makes Java deserialization vulnerabilities easy to exploit and [Stephen Breen](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) demonstrated the majority of Java web servers are vulnerable. I thought it would be interesting to see how common deserialization is in open source Java projects. 

## Searching GitHub

I developed a [script](https://github.com/philwantsfish/GitHubSearch) to search and sort the most popular repositories on GitHub by language. Searching the 200 most popular Java repositories for uses of `new ObjectInputStream` showed:

<img class="img-responsive" src="{{site.baseurl}}/files/java-deserialized-chart.png" alt="GitHub top 200 chart" width="600">

16 percent of Java repositories explicitly create and use an ObjectInputStream. Using an ObjectInputStream doesn't mean the program is vulnerable - a vulnerability exists when the ObjectInputStream processes data from an untrusted source and the class path contains a "gadget chain".

The majority of the above projects, especially Android projects, use serialization to persist an object to disk and restore it later. If an attacker can modify files then this bug is unlikely to elevate their privileges. But there is a few projects that accept data remotely and deserialize it! Lets explore attempting to exploit one of them.

*Note: The real percentage of Java projects using serialization is likely much higher because popular frameworks internally use serialization.*

## Serialization in Gradle

When writing this blog post Gradle was the 101st most popular Java project on GitHub with more than 3500 stars. This project is an extremely popular build system for Java and is the standard build system for Android.

Gradle deserializes data in the [ObjectSocketWrapper](https://github.com/gradle/gradle/blob/f490bdf61bd9b4f5383cd9fb0d8ffbca93da8c32/subprojects/ui/src/main/java/org/gradle/foundation/ipc/basic/ObjectSocketWrapper.java#L51) class. This class is used in the jetty subproject [here](https://github.com/gradle/gradle/blob/f490bdf61bd9b4f5383cd9fb0d8ffbca93da8c32/subprojects/jetty/src/main/java/org/gradle/api/plugins/jetty/internal/Jetty6PluginServer.java#L111) and the ui subproject [here](https://github.com/gradle/gradle/blob/f490bdf61bd9b4f5383cd9fb0d8ffbca93da8c32/subprojects/ui/src/main/java/org/gradle/foundation/ipc/gradle/TaskListClientProtocol.java#L127) and [here](https://github.com/gradle/gradle/blob/f490bdf61bd9b4f5383cd9fb0d8ffbca93da8c32/subprojects/ui/src/main/java/org/gradle/foundation/ipc/gradle/ExecuteGradleCommandClientProtocol.java#L82). Both of these plugins open a socket and wait for a client to connect and send serialized data.

The ui subproject is easy to work with, it can be launched by executing *./gradlew --gui*.

{% highlight bash %}
$ ./gradlew --gui &
[1] 62481
$ lsof -i
... snip ...
java      59699 pokeefe  182u  IPv6 0xb34e0a81bf8fe953      0t0  TCP *:60024 (LISTEN)
... snip ...
{% endhighlight %}

An ephemeral port opened and is listening for connections on all interfaces.

## Confirming the vulnerability

To confirm the vulnerability lets send a serialized object and confirm the program attempted to deserialized it. I built the project in Intellij Idea and attached breakpoints on the socket accept and readObject method. Sending an arbitrary payload from ysoserial to the socket:

{% highlight bash %}
$ lsof -i
... snip ...
java      60042 pokeefe   85u  IPv6 0xb34e0a81a122b933      0t0  TCP *:61973 (LISTEN)
... snip ...
$ java -jar ysoserial-0.0.5-SNAPSHOT-all.jar CommonsBeanutils1 "" > /tmp/payloads/commonsbeanutils1
$ cat /tmp/payloads/commonsbeanutils1 | nc 127.0.0.1 61973

{% endhighlight %}

Stepping through the readObject method confirms the program attempted to deserialize the CommonsBeanutils1 payload

<img class="img-responsive" src="{{site.baseurl}}/files/intellij-debug.png" alt="Intellij Debugging" width="800">

At this point we can consider the ui subproject and jetty subproject vulnerable. Successful exploitation depends on finding a gadget chain in the projects classpath.

## Exploitation

Each projects dependencies can be listed using the gradle task *dependencies* and executing ysoserial with no arguments lists the known gadget chains. Cross checking these two lists:
 
 <table class="table table-bordered table-hover">
   <thead>
    <th>Library</th>
    <th>Vulnerable version</th>
    <th>ui-subproject version</th>
    <th>Exploitable</th>
  </thead>
  <tbody>
    <tr>
      <td>BeanShell1</td>
      <td>org.beanshell:bsh:2.0b5</td>
      <td>n/a</td>
      <td>N</td>
    </tr>
    <tr><td>  C3P0 </td><td> com.mchange:c3p0:0.9.5.2, com.mchange:mchange-commons-java:0.2.11 </td><td> n/a </td><td> N </td></tr>
    <tr><td>  CommonsBeanutils1 </td><td> commons-beanutils:commons-beanutils:1.9.2, commons-collections:commons-collections:3.1, commons-logging:commons-logging:1.2 </td><td> n/a </td><td> N </td></tr>
    <tr><td>  CommonsCollections1 </td><td> commons-collections:commons-collections:3.1 </td><td> Commons collections 3.2.2 </td><td> N </td></tr>
    <tr><td>  CommonsCollections2 </td><td> org.apache.commons:commons-collections4:4.0 </td><td> Commons collections 3.2.2 </td><td> N </td></tr>
    <tr><td>  commonscollections3 </td><td> commons-collections:commons-collections:3.1 </td><td> commons collections 3.2.2 </td><td> n </td></tr>
    <tr><td>  commonscollections4 </td><td> org.apache.commons:commons-collections4:4.0 </td><td> commons collections 3.2.2 </td><td> n </td></tr>
    <tr><td>  commonscollections5 </td><td> commons-collections:commons-collections:3.1 </td><td> commons collections 3.2.2 </td><td> n </td></tr>
    <tr><td>  fileupload1 </td><td> commons-fileupload:commons-fileupload:1.3.1, commons-io:commons-io:2.4 </td><td> n/a </td><td> n </td></tr>
    <tr><td>  groovy1 </td><td> org.codehaus.groovy:groovy:2.3.9 </td><td>  groovy 2.4.4 </td><td> n </td></tr>
    <tr><td>  jdk7u21 </td><td> jdk7u21 </td><td>  </td><td> ? </td></tr>
    <tr><td>  jython1 </td><td> org.python:jython-standalone:2.5.2 </td><td> n/a </td><td> n </td></tr>
    <tr><td>  spring1 </td><td> org.springframework:spring-core:4.1.4.release, org.springframework:spring-beans:4.1.4.release </td><td> n/a </td><td> n </td></tr>
    <tr><td>  Spring2 </td><td> org.springframework:spring-core:4.1.4.RELEASE, org.springframework:spring-aop:4.1.4.RELEASE, aopalliance:aopalliance:1.0, commons-logging:commons-logging:1.2 </td><td> n/a </td><td> N </td></tr>
  </tbody>
 </table>
<br/>

The projects dependencies are all non-vulnerable versions. Downgrading to [Gradle 2.12](https://gradle.org/gradle-download/) and checking the library versions again shows commons-collections 3.2.1. The commons-collections5 payload in ysoserial successful executes an arbitary commands. 

Looking through the Gradle release notes this vulnerability was not mentioned, I suspect the developers were unaware of it and were just upgrading their libraries. I've requested CVE-2016-6199 to track this vulnerability. 

## Concluding thoughts

If you are running Gradle 2.12 or earlier you should upgrade. While this post details exploiting the UI subproject, the Jetty subproject is similarly vulnerable. The searching script found more projects that appear vulnerable. It might also be interesting to identify and search for framework APIs that wrap serialization. 
