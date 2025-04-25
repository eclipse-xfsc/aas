package eu.xfsc.aas.cache.caffeine;

import java.time.Duration;
import java.util.Collection;
import java.util.Map;

import org.checkerframework.checker.nullness.qual.Nullable;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.RemovalListener;

import eu.xfsc.aas.cache.DataCache;
import eu.xfsc.aas.cache.TriConsumer;

public class CaffeineDataCache<K, V> implements DataCache<K, V> {
    
    private Cache<K, V> dataCache;
    
    @SuppressWarnings("unchecked")
    public CaffeineDataCache(int cacheSize, Duration ttl, TriConsumer<K, V> synchronizer) {
        Caffeine<K, V> cache = (Caffeine<K, V>) Caffeine.newBuilder().expireAfterAccess(ttl); 
        if (cacheSize > 0) {
            cache = cache.maximumSize(cacheSize);
        } 
        if (synchronizer != null) {
            cache = cache.removalListener(new DataListener<>(synchronizer));
        }
        dataCache = cache.build(); 
    }
    

    @Override
    public void clean() {
        dataCache.cleanUp();
    }

    @Override
    public V get(K key) {
        return dataCache.getIfPresent(key);
    }

    @Override
    public Map<K, V> getAll() {
        return dataCache.asMap();
    }
    
    @Override
    public Map<K, V> getAll(Collection<? extends K> keys) {
        return dataCache.getAllPresent(keys);
    }

    @Override
    public void put(K key, V value) {
        dataCache.put(key, value);
    }

    @Override
    public void putAll(Map<? extends K, ? extends V> entries) {
        dataCache.putAll(entries);
    }

    @Override
    public void remove(K key) {
        dataCache.invalidate(key);
    }

    @Override
    public long estimatedSize() {
        return dataCache.estimatedSize();
    }
    
    
    private static class DataListener<K, V> implements RemovalListener<K, V> {
        
        private TriConsumer<K, V> synchronizer;
        
        DataListener(TriConsumer<K, V> synchronizer) {
            this.synchronizer = synchronizer;
        }

        @Override
        public void onRemoval(@Nullable K key, @Nullable V value, RemovalCause cause) {
            synchronizer.apply(key, value, cause == RemovalCause.REPLACED);
        }
        
    }

}
