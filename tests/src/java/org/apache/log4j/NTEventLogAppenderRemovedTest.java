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

package org.apache.log4j;

import junit.framework.TestCase;

import java.io.StringReader;
import java.util.Properties;

import org.apache.log4j.xml.DOMConfigurator;

/**
 * Regression tests for the removal of NTEventLogAppender (sonatype-2010-0053).
 *
 * <p>NTEventLogAppender called <code>System.loadLibrary</code> from its static
 * initializer, so merely instantiating it (for example from a configuration
 * file) searched the library path, which on Windows includes the current
 * directory and PATH, for <code>NTEventLogAppender*.dll</code>. A planted DLL
 * would then be loaded and executed (DLL preloading). The appender has been
 * removed; these tests make sure no configuration route can trigger that
 * native library load any more.
 */
public class NTEventLogAppenderRemovedTest extends TestCase {

  private static final String NT_APPENDER_CLASS =
      "org.apache.log4j.nt.NTEventLogAppender";

  public NTEventLogAppenderRemovedTest(final String name) {
    super(name);
  }

  public void tearDown() {
    LogManager.resetConfiguration();
  }

  /**
   * Loading the class by name must not be possible, so its native library
   * loading static initializer can never run.
   */
  public void testClassIsNotAvailable() {
    try {
      Class.forName(NT_APPENDER_CLASS);
      fail(NT_APPENDER_CLASS + " must not be available");
    } catch (ClassNotFoundException expected) {
      // expected: the appender has been removed
    } catch (LinkageError e) {
      fail("loading " + NT_APPENDER_CLASS
          + " attempted to load a native library: " + e);
    }
  }

  /**
   * A properties configuration naming NTEventLogAppender must not trigger a
   * native library load and must not install the appender.
   */
  public void testPropertyConfiguratorDoesNotLoadNativeLibrary() {
    Properties props = new Properties();
    props.put("log4j.rootLogger", "DEBUG, NT");
    props.put("log4j.appender.NT", NT_APPENDER_CLASS);
    props.put("log4j.appender.NT.Source", "Log4j");
    props.put("log4j.appender.NT.layout", "org.apache.log4j.SimpleLayout");
    try {
      PropertyConfigurator.configure(props);
    } catch (LinkageError e) {
      fail("configuring " + NT_APPENDER_CLASS
          + " attempted to load a native library: " + e);
    }
    assertNull(Logger.getRootLogger().getAppender("NT"));
  }

  /**
   * An XML configuration naming NTEventLogAppender must not trigger a
   * native library load and must not install the appender.
   */
  public void testDOMConfiguratorDoesNotLoadNativeLibrary() {
    String xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
        + "<!DOCTYPE log4j:configuration SYSTEM \"log4j.dtd\">\n"
        + "<log4j:configuration xmlns:log4j=\"http://jakarta.apache.org/log4j/\">\n"
        + "  <appender name=\"NT\" class=\"" + NT_APPENDER_CLASS + "\">\n"
        + "    <param name=\"Source\" value=\"Log4j\"/>\n"
        + "    <layout class=\"org.apache.log4j.SimpleLayout\"/>\n"
        + "  </appender>\n"
        + "  <root>\n"
        + "    <level value=\"debug\"/>\n"
        + "    <appender-ref ref=\"NT\"/>\n"
        + "  </root>\n"
        + "</log4j:configuration>\n";
    try {
      new DOMConfigurator().doConfigure(new StringReader(xml),
          LogManager.getLoggerRepository());
    } catch (LinkageError e) {
      fail("configuring " + NT_APPENDER_CLASS
          + " attempted to load a native library: " + e);
    }
    assertNull(Logger.getRootLogger().getAppender("NT"));
  }
}
