package eu.xfsc.aas.cache;

@FunctionalInterface
public interface TriConsumer<K, V> {

    void apply(K key, V value, boolean replaced);

    //default <V> TriFunction<A, B, C, V> andThen(
    //                            Function<? super R, ? extends V> after) {
    //    Objects.requireNonNull(after);
    //    return (A a, B b, C c) -> after.apply(apply(a, b, c));
    //}
}