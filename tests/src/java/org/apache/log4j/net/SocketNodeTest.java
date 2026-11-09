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

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import junit.framework.TestCase;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Exercises {@link SocketNode}, the receiving end of SocketAppender used by
 * SocketServer and SimpleSocketServer, against CVE-2023-26464.
 */
public class SocketNodeTest extends TestCase {

    /**
     * Collects the events SocketNode hands to the hierarchy.
     */
    static class CollectingAppender extends AppenderSkeleton {
        final List events = new Vector();

        protected void append(LoggingEvent event) {
            events.add(event);
        }

        public void close() {
        }

        public boolean requiresLayout() {
            return false;
        }
    }

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private Socket acceptedSocket;
    private Hierarchy hierarchy;
    private CollectingAppender appender;

    public SocketNodeTest(final String testName) {
        super(testName);
    }

    protected void setUp() throws Exception {
        serverSocket = new ServerSocket(0);
        clientSocket = new Socket(InetAddress.getByName("127.0.0.1"), serverSocket.getLocalPort());
        acceptedSocket = serverSocket.accept();
        hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
        appender = new CollectingAppender();
        hierarchy.getRootLogger().addAppender(appender);
    }

    protected void tearDown() throws Exception {
        clientSocket.close();
        acceptedSocket.close();
        serverSocket.close();
    }

    /**
     * Sends the events from a separate thread, optionally closing the
     * connection afterwards.
     */
    private Thread send(final LoggingEvent[] events, final boolean close,
                        final IOException[] failure) {
        Thread writer = new Thread(new Runnable() {
            public void run() {
                try {
                    ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
                    for (int i = 0; i < events.length; i++) {
                        oos.writeObject(events[i]);
                    }
                    oos.flush();
                    if (close) {
                        oos.close();
                    }
                } catch (IOException e) {
                    failure[0] = e;
                }
            }
        }, "SocketNodeTest-writer");
        writer.setDaemon(true);
        writer.start();
        return writer;
    }

    private Thread startNode() {
        Thread nodeThread = new Thread(new SocketNode(acceptedSocket, hierarchy),
                "SocketNodeTest-node");
        nodeThread.setDaemon(true);
        nodeThread.start();
        return nodeThread;
    }

    /**
     * CVE-2023-26464: an event whose MDC carries deeply nested HashSets must
     * be rejected and the connection closed instead of keeping the receiving
     * thread busy computing hash codes. The client keeps the connection open,
     * so the node can only stop because the payload was rejected.
     */
    public void testNestedCollectionPayloadClosesConnection() throws Exception {
        Map mdc = new HashMap();
        mdc.put("payload", HardenedObjectInputStreamTest.createNestedHashSets(
                HardenedObjectInputStreamTest.NESTING_DEPTH));
        IOException[] failure = new IOException[1];
        Thread writer = send(new LoggingEvent[] {
                HardenedObjectInputStreamTest.createEvent("evil", mdc) }, false, failure);

        Thread nodeThread = startNode();
        nodeThread.join(HardenedObjectInputStreamTest.TIMEOUT_MILLIS);
        writer.join(HardenedObjectInputStreamTest.TIMEOUT_MILLIS);

        assertFalse("SocketNode is still deserializing the nested collection payload"
                + " (CVE-2023-26464 denial of service)", nodeThread.isAlive());
        assertTrue("SocketNode should close the connection", acceptedSocket.isClosed());
        assertEquals("The malicious event must not be logged", 0, appender.events.size());
    }

    /**
     * Each event read by SocketNode gets its own collection budget: a single
     * connection keeps accepting events carrying an MDC Hashtable well past
     * MAX_COLLECTION_COUNT events.
     */
    public void testManyEventsWithMDCAreLogged() throws Exception {
        int eventCount = HardenedObjectInputStream.MAX_COLLECTION_COUNT * 2;
        LoggingEvent[] events = new LoggingEvent[eventCount];
        for (int i = 0; i < eventCount; i++) {
            Map mdc = new HashMap();
            mdc.put("requestId", "req-" + i);
            events[i] = HardenedObjectInputStreamTest.createEvent("message " + i, mdc);
        }
        IOException[] failure = new IOException[1];
        Thread writer = send(events, true, failure);

        Thread nodeThread = startNode();
        nodeThread.join(HardenedObjectInputStreamTest.TIMEOUT_MILLIS);
        writer.join(HardenedObjectInputStreamTest.TIMEOUT_MILLIS);

        assertNull("Sending failed: " + failure[0], failure[0]);
        assertFalse("SocketNode should stop at end of stream", nodeThread.isAlive());
        assertEquals(eventCount, appender.events.size());
        for (int i = 0; i < eventCount; i++) {
            LoggingEvent event = (LoggingEvent) appender.events.get(i);
            assertEquals("message " + i, event.getRenderedMessage());
            assertEquals("req-" + i, event.getMDC("requestId"));
        }
    }
}
