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
package org.apache.log4j.chainsaw;

import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import org.apache.log4j.net.HardenedObjectInputStreamTest;

/**
 * Exercises the Chainsaw {@link LoggingReceiver} against CVE-2023-26464.
 */
public class LoggingReceiverTest extends TestCase {

    private static final int TIMEOUT_MILLIS = 30000;

    /**
     * Twice the number of collections HardenedObjectInputStream accepts per
     * event; every event below carries one MDC Hashtable.
     */
    private static final int EVENT_COUNT = 64;

    private MyTableModel model;
    private Socket clientSocket;

    public LoggingReceiverTest(final String testName) {
        super(testName);
    }

    protected void setUp() throws Exception {
        ServerSocket probe = new ServerSocket(0);
        int port = probe.getLocalPort();
        probe.close();

        model = new MyTableModel();
        LoggingReceiver receiver = new LoggingReceiver(model, port);
        receiver.start();
        clientSocket = new Socket(InetAddress.getByName("127.0.0.1"), port);
        clientSocket.setSoTimeout(TIMEOUT_MILLIS);
    }

    protected void tearDown() throws Exception {
        clientSocket.close();
    }

    /**
     * CVE-2023-26464: an event whose MDC carries deeply nested HashSets must
     * be rejected and the connection closed instead of keeping Chainsaw busy
     * computing hash codes. The client keeps the connection open, so the
     * receiver can only close it because the payload was rejected.
     */
    public void testNestedCollectionPayloadClosesConnection() throws Exception {
        Map mdc = new HashMap();
        mdc.put("payload", HardenedObjectInputStreamTest.createNestedHashSets(
                HardenedObjectInputStreamTest.NESTING_DEPTH));
        ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
        oos.writeObject(HardenedObjectInputStreamTest.createEvent("evil", mdc));
        oos.flush();

        InputStream in = clientSocket.getInputStream();
        try {
            assertEquals("Chainsaw should close the connection", -1, in.read());
        } catch (SocketTimeoutException e) {
            fail("Chainsaw is still deserializing the nested collection payload"
                    + " (CVE-2023-26464 denial of service)");
        } catch (SocketException e) {
            // connection reset: the receiver closed the connection
        }

        // let the model's processor thread pick up pending events
        Thread.sleep(1500);
        assertEquals("The malicious event must not be shown", 0, model.getRowCount());
    }

    /**
     * Each event read by Chainsaw gets its own collection budget: a single
     * connection keeps accepting events carrying an MDC Hashtable well past
     * the per-event collection limit.
     */
    public void testManyEventsWithMDCAreReceived() throws Exception {
        int eventCount = EVENT_COUNT;
        ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
        for (int i = 0; i < eventCount; i++) {
            Map mdc = new HashMap();
            mdc.put("requestId", "req-" + i);
            oos.writeObject(HardenedObjectInputStreamTest.createEvent("message " + i, mdc));
        }
        oos.flush();

        long deadline = System.currentTimeMillis() + TIMEOUT_MILLIS;
        while (model.getRowCount() < eventCount && System.currentTimeMillis() < deadline) {
            Thread.sleep(200);
        }
        assertEquals(eventCount, model.getRowCount());
    }
}
