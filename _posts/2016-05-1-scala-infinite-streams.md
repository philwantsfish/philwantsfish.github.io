---
layout: post
title: Infinite streams and prime numbers
excerpt: "Scala Streams are similar to Lists but evalute their elements lazily. This small detail makes a world of difference. This post explores Streams and how they can encapsulate infinate sets."
permalink: "scala/streamsandprimes"
categories: Scala
tags:
  - Scala
---
I was playing with Streams after reading the strictness chapter in [Functional Programming in Scala](https://www.manning.com/books/functional-programming-in-scala) and thought I'd share my ramblings. Streams and Lists are similar data structures, except Streams compute their elements lazily. Because not all elements are computed during construction it is possible to implement infinitely long Streams.

## Fibonacci Sequence

Generating the Fibbonacci sequence is a simple example from the Streams [scaladoc](http://www.scala-lang.org/api/2.11.8/#scala.collection.immutable.Stream) page

{% highlight Scala %}
object InfiniteStreams {
  def fib: Stream[Int] = fibFrom(0, 1)
  def fibFrom(a: Int, b: Int): Stream[Int] = a #:: fibFrom(b, a + b)
}
{% endhighlight %}

The `#::` operator will compute the right side lazily. We can use the Stream the same as a List, for example, taking the first 10 elements of the sequence

{% highlight Scala %}
"fib" should "implement the fibonacci sequence" in {
  fib.take(10) shouldBe Stream(0, 1, 1, 2, 3, 5, 8, 13, 21, 34)
}
{% endhighlight %}

## The unfold function

The `fibFrom` method takes the current state of the sequence as inputs, calculates the next element, and recurses with the next state. We can generalize these steps with a function called `unfold`, which takes an initial state and a function to produce the next element and state.

{% highlight Scala %}
def unfold[A, S](z: S)(f: S => Option[(A, S)]): Stream[A] = {
  f(z) match {
    case Some((a, s)) => a #:: unfold(s)(f)
    case None => Stream.empty
}
{% endhighlight %}

This implementation allows the Stream to terminate when the function returns `None`

## Algorithm for finding primes

The [Sieve of Eratosthenes](https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes) is an old and simple algorithm for finding prime numbers. From wikipedia, "It does so by iteratively marking as composite (i.e., not prime) the multiples of each prime, starting with the multiples of 2"

Using this idea we can generate an infinite stream of prime numbers. We can implement the algorithm using `unfold` in the following steps:

1. The starting state is the number 2 and an empty set of prime checking functions
2. Sequentially check each number for primeness until a prime is found
3. Convert the prime to a check function and add it to the prime checking functions
4. Return the prime number and the new set of prime checking functions

## An infinite stream of prime numbers

The algorithm implemented with `unfold`

{% highlight Scala %}
def primes: Stream[Int] = {
  // The set of prime checking functions mentioned in step 1
  val checkPrimeFunctions: Seq[Int => Boolean] = Seq()

  // A function to turn a prime into a function mentioned in step 3
  val makeCheckPrimeFunction: Int => Int => Boolean = a => b => b % a == 0

  // A helper function to check if a number is prime
  def isComposite(fs: Seq[Int => Boolean], num: Int): Boolean = fs.exists { f => f(num) }

  // The infinite stream implemented with unfold
  1 #:: unfold((2, checkPrimeFunctions)) {
    case (i, fs) =>
      def go(num: Int, ffs: Seq[Int => Boolean]): (Int, (Int, Seq[Int=>Boolean])) = {
        if(isComposite(fs, num)) go(num+1, ffs)
        else (num, (num+1, ffs :+ makeCheckPrimeFunction(num)))
      }
      Some(go(i, fs))
  }
}
{% endhighlight %}

We can use the Stream like so:

{% highlight Scala %}
"primes" should "implement a stream of prime numebrs" in {
  primes.take(10) shouldBe Stream(1, 2, 3, 5, 7, 11, 13, 17, 19, 23)
}
{% endhighlight %}
