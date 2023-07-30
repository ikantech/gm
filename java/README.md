BouncyCastle好像除了Java语言版，还有`.Net`版的，本文主要向大家分享Java语言如何使用BouncyCastle算法库中已经实现好的国密SM2、SM3及SM4算法。

## 项目依赖

建一个空的Maven项目，添加以下依赖

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.70</version>
</dependency>
```

另外，本文出发点是使用BouncyCastle已经造好的轮子，并不打算用Java语言重新造一个国密算法的轮子。原因有两点吧：   
* 一是BouncyCastle已经写的很全面了，不考虑项目体积和性能完全没必要;
* 二是Java语言不好做汇编优化，性能跟C/C++经汇编优化的版本肯定多多少少有些差距，个人感觉意义不大。

> 提示：本文在junit中分享BouncyCastle算法库的使用方法，不额外进行封装，留更多空间给大家自由发挥
