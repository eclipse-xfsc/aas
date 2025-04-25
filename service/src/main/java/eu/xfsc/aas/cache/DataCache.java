package eu.xfsc.aas.cache;

import java.util.Collection;
import java.util.Map;

public interface DataCache<K, V> {

    void clean();
    V get(K key);
    Map<K, V> getAll();
    Map<K, V> getAll(Collection<? extends K> keys);
    void put(K key, V value);
    void putAll(Map<? extends K, ? extends V> entries);
    void remove(K key);
    long estimatedSize();
    
}
