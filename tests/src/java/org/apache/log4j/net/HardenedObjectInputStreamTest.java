/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    /**
     * Upper bound for a single malicious read to be rejected. Without the
     * collection limit the payloads below never finish deserializing.
     */
    public static final long TIMEOUT_MILLIS = 30000;

    /**
     * Number of levels of the nested payloads; far beyond what the
     * unprotected hashCode() computation can ever complete.
     */
    public static final int NESTING_DEPTH = 100;

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * Builds the CVE-2023-26464 payload: deeply nested HashSets forming a
     * DAG whose hashCode() costs O(2^depth) once it is deserialized.
     */
    public static Set createNestedHashSets(int depth) {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < depth; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    /**
     * Same DAG as {@link #createNestedHashSets(int)} but built from maps
     * whose keys are the nested maps, so that deserializing a level hashes
     * the whole sub-graph below it.
     */
    static Map createNestedMaps(Class mapClass, int depth) throws Exception {
        Map root = (Map) mapClass.newInstance();
        Map m1 = root;
        Map m2 = (Map) mapClass.newInstance();
        for (int i = 0; i < depth; i++) {
            Map t1 = (Map) mapClass.newInstance();
            Map t2 = (Map) mapClass.newInstance();
            t1.put("foo", "bar");
            m1.put(t1, "v");
            m1.put(t2, "v");
            m2.put(t1, "v");
            m2.put(t2, "v");
            m1 = t1;
            m2 = t2;
        }
        return root;
    }

    /**
     * Creates a LoggingEvent as sent by SocketAppender, carrying the given
     * MDC properties.
     */
    public static LoggingEvent createEvent(String message, Map mdc) {
        return new LoggingEvent(Logger.class.getName(),
                Logger.getLogger("org.apache.log4j.net.HardenedObjectInputStreamTest"),
                System.currentTimeMillis(), Level.INFO, message, "main",
                null, null, null, mdc);
    }

    /**
     * Reads one object on a separate thread so that a regression shows up as
     * a test failure instead of a hanging build.
     *
     * @return the throwable raised by the read, or null if it succeeded
     */
    private Throwable readInBoundedTime(final HardenedObjectInputStream hois)
            throws InterruptedException {
        final Throwable[] failure = new Throwable[1];
        Thread reader = new Thread(new Runnable() {
            public void run() {
                try {
                    hois.readAdaptedObject();
                } catch (Throwable t) {
                    failure[0] = t;
                }
            }
        }, "HardenedObjectInputStreamTest-reader");
        reader.setDaemon(true);
        reader.start();
        reader.join(TIMEOUT_MILLIS);
        assertFalse("Deserialization did not complete within " + TIMEOUT_MILLIS
                + " ms (CVE-2023-26464 denial of service)", reader.isAlive());
        return failure[0];
    }

    private void assertRejected(Throwable failure) {
        assertNotNull("Nested collection payload should be rejected", failure);
        if (failure instanceof InvalidObjectException) {
            assertTrue("Should mention collection limit: " + failure.getMessage(),
                    failure.getMessage().indexOf("collection") != -1);
        } else if (!(failure instanceof java.io.InvalidClassException)) {
            // On JDK 9+ a configured ObjectInputFilter may reject the payload
            // first with an InvalidClassException; anything else is a failure.
            fail("Unexpected exception: " + failure);
        }
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") != -1);
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * CVE-2023-26464 with a deeply nested Hashtable (the MDC type of
     * LoggingEvent).
     */
    public void testDeeplyNestedHashtableRejected() throws Exception {
        byte[] serialized = serialize(createNestedMaps(Hashtable.class, NESTING_DEPTH));
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0]);
        try {
            assertRejected(readInBoundedTime(hois));
        } finally {
            hois.close();
        }
    }

    /**
     * CVE-2023-26464 with a deeply nested HashMap.
     */
    public void testDeeplyNestedHashMapRejected() throws Exception {
        byte[] serialized = serialize(createNestedMaps(HashMap.class, NESTING_DEPTH));
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0]);
        try {
            assertRejected(readInBoundedTime(hois));
        } finally {
            hois.close();
        }
    }

    /**
     * CVE-2023-26464 as delivered to SocketNode and Chainsaw: a LoggingEvent
     * whose MDC carries the nested collection payload, read through
     * HardenedLoggingEventInputStream.
     */
    public void testLoggingEventWithNestedCollectionsRejected() throws Exception {
        Map mdc = new HashMap();
        mdc.put("payload", createNestedHashSets(NESTING_DEPTH));
        byte[] serialized = serialize(createEvent("evil", mdc));

        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(serialized));
        try {
            assertRejected(readInBoundedTime(hleis));
        } finally {
            hleis.close();
        }
    }

    /**
     * readAdaptedObject() gives each event its own collection budget, so a
     * long-lived connection carrying many events with an MDC keeps working.
     */
    public void testCollectionBudgetIsPerEvent() throws Exception {
        int eventCount = HardenedObjectInputStream.MAX_COLLECTION_COUNT * 2;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < eventCount; i++) {
            Map mdc = new HashMap();
            mdc.put("requestId", "req-" + i);
            oos.writeObject(createEvent("message " + i, mdc));
        }
        oos.close();

        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(bos.toByteArray()));
        for (int i = 0; i < eventCount; i++) {
            LoggingEvent event = (LoggingEvent) hleis.readAdaptedObject();
            assertEquals("message " + i, event.getRenderedMessage());
            assertEquals("req-" + i, event.getMDC("requestId"));
        }
        hleis.close();
    }

    private byte[] serializeListOfSets(int setCount) throws IOException {
        List list = new ArrayList();
        for (int i = 0; i < setCount; i++) {
            Set set = new HashSet();
            set.add("element-" + i);
            list.add(set);
        }
        return serialize(list);
    }

    /**
     * Exactly MAX_COLLECTION_COUNT collections (the sets plus the list) are
     * accepted.
     */
    public void testCollectionCountAtLimitAllowed() throws Exception {
        byte[] serialized = serializeListOfSets(HardenedObjectInputStream.MAX_COLLECTION_COUNT - 1);
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0]);
        Object result = hois.readAdaptedObject();
        assertTrue(result instanceof List);
        assertEquals(HardenedObjectInputStream.MAX_COLLECTION_COUNT - 1, ((List) result).size());
        hois.close();
    }

    /**
     * One collection more than MAX_COLLECTION_COUNT is rejected.
     */
    public void testCollectionCountAboveLimitRejected() throws Exception {
        byte[] serialized = serializeListOfSets(HardenedObjectInputStream.MAX_COLLECTION_COUNT);
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0]);
        try {
            hois.readAdaptedObject();
            fail("More than MAX_COLLECTION_COUNT collections should be rejected");
        } catch (InvalidObjectException e) {
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") != -1);
        } finally {
            hois.close();
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }
}
