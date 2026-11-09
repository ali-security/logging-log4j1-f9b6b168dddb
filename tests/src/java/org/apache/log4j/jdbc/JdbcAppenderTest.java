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
package org.apache.log4j.jdbc;

import junit.framework.TestCase;

import org.apache.log4j.Appender;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.VectorErrorHandler;
import org.apache.log4j.xml.XLevel;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class JdbcAppenderTest extends TestCase {
  private static final String TEST_INPUT_PREFIX = "input/";

  // Closing the last connection to "in-memory h2" removes the database
  // So we keep the connection during the test
  // The logger opens its own connection
  Connection con;

  public JdbcAppenderTest(final String name) {
    super(name);
  }

  public void setUp() throws Exception {
    Class.forName("org.h2.Driver");
    con = DriverManager.getConnection("jdbc:h2:mem:test_db");
    Statement st = con.createStatement();
    try {
      st.execute("create table logs(level varchar(100),location varchar(100),message varchar(100),message2 varchar(100))");
    } finally {
      st.close();
    }
  }

  public void tearDown() throws SQLException {
    LogManager.shutdown();
    con.close();
  }

  public void testVerifyJdbcInsecure() throws SQLException {
    String secureJdbcReplacement = "org.apache.log4j.jdbc.JDBCAppender.secure_jdbc_replacement";
    System.setProperty(secureJdbcReplacement, "false");
    try {
      PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_bufferSize1.properties");
      Appender jdbcAppender = LogManager.getRootLogger().getAppender("A");
      // Keep errors
      VectorErrorHandler errorHandler = new VectorErrorHandler();
      jdbcAppender.setErrorHandler(errorHandler);

      Logger logger = Logger.getLogger(JdbcAppenderTest.class);

      String oldThreadName = Thread.currentThread().getName();
      try {
        Thread.currentThread().setName("main");
        logger.debug("message with '' quote");
        assertEquals(
          "batchSize=1, so messages should be added immediately",
          "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
          joinSorted(getMessages()));

        // It should fail
        logger.fatal("message with ' quote");

        assertEquals(
          "Inserting a message with ' should cause failure in insecure mode, so only one message should be in the DB",
          "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
          joinSorted(getMessages()));

        StringBuffer exceptions = new StringBuffer();
        StringBuffer errorCodes = new StringBuffer();
        for (int i = 0; i < errorHandler.size(); i++) {
          Exception ex = errorHandler.getException(i);
          exceptions.append(ex);
          // SQLSTATE class 42 is "syntax error or access rule violation"
          errorCodes.append(
            ex instanceof SQLException
              ? ("SQLException.getSQLState() class = "
                 + String.valueOf(((SQLException) ex).getSQLState()).substring(0, 2))
              : ("SQL Exception expected, got " + ex.getClass()));
          exceptions.append('\n');
          errorCodes.append('\n');
        }
        assertEquals(
          "Logging a message with ' should trigger SQLException 'Syntax error in SQL statement...' when using insecure JDBCAppender mode, actual exceptions are\n" + exceptions,
          "SQLException.getSQLState() class = 42\n",
          errorCodes.toString()
        );
      } finally {
        Thread.currentThread().setName(oldThreadName);
      }
    } finally {
      System.getProperties().remove(secureJdbcReplacement);
    }
  }

  public void testVerifyJdbcBufferSize1() throws SQLException {
    PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_bufferSize1.properties");

    Logger logger = Logger.getLogger(JdbcAppenderTest.class);

    String oldThreadName = Thread.currentThread().getName();
    try {
      Thread.currentThread().setName("main");
      logger.debug("message with ' quote");
      assertEquals(
        "batchSize=1, so messages should be added immediately",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
        joinSorted(getMessages()));

      logger.fatal("message with \" quote");

      assertEquals(
        "batchSize=1, so two messages should be in DB after two logging calls",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n" +
          "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
        joinSorted(getMessages()));
    } finally {
      Thread.currentThread().setName(oldThreadName);
    }
  }

  public void testVerifyJdbcBufferSize2() throws SQLException {
    PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_bufferSize2.properties");

    Logger logger = Logger.getLogger(JdbcAppenderTest.class);

    String oldThreadName = Thread.currentThread().getName();
    try {
      Thread.currentThread().setName("main");
      logger.log(XLevel.TRACE, "xtrace message");
      logger.debug("message with ' quote");
      logger.info("message with \" quote");
      logger.warn("?");
      // bufferSize=2, so this messsage won't yet be stored to the db
      logger.error("m4");

      assertEquals(
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n" +
          "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n" +
          "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n" +
          "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
        joinSorted(getMessages()));

      logger.fatal("m5");

      assertEquals(
        "Logging m5 message should trigger buffer flush for both m4 and m5",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n" +
          "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n" +
          "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n" +
          "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n" +
          "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n" +
          "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
        joinSorted(getMessages()));
    } finally {
      Thread.currentThread().setName(oldThreadName);
    }
  }

  /**
   * CVE-2022-23305: a crafted log message must be stored verbatim and must
   * not be able to inject additional SQL statements.
   */
  public void testSqlInjectionViaMessageIsNotExecuted() throws SQLException {
    PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_bufferSize1.properties");
    Appender jdbcAppender = LogManager.getRootLogger().getAppender("A");
    VectorErrorHandler errorHandler = new VectorErrorHandler();
    jdbcAppender.setErrorHandler(errorHandler);

    Logger logger = Logger.getLogger(JdbcAppenderTest.class);
    logger.info("first");
    // Closes the values(...) list and appends a statement wiping the table
    String payload = "x','y'); delete from logs; --";
    logger.warn(payload);

    assertEquals("No errors expected, got " + errorHandler.size(), 0, errorHandler.size());
    assertEquals(
      "Injected SQL must not be executed, the payload must be stored verbatim",
      "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; first;  org.apache.log4j.jdbc.JdbcAppenderTest INFO first\n" +
        "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; " + payload + ";  org.apache.log4j.jdbc.JdbcAppenderTest WARN " + payload + "\n",
      joinSorted(getMessages()));
  }

  /**
   * CVE-2022-23305: crafted values in the MDC (%X) or NDC (%x), e.g. copied from
   * request headers, must not be able to inject additional SQL statements.
   */
  public void testSqlInjectionViaMdcAndNdcIsNotExecuted() throws SQLException {
    PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_mdc_ndc.properties");
    Appender jdbcAppender = LogManager.getRootLogger().getAppender("A");
    VectorErrorHandler errorHandler = new VectorErrorHandler();
    jdbcAppender.setErrorHandler(errorHandler);

    Logger logger = Logger.getLogger(JdbcAppenderTest.class);
    String mdcPayload = "u','m','n'); delete from logs; --";
    String ndcPayload = "n'); delete from logs; --";
    try {
      MDC.put("user", "alice");
      NDC.push("ctx");
      logger.info("first");
      NDC.pop();

      MDC.put("user", mdcPayload);
      NDC.push(ndcPayload);
      logger.warn("second");
    } finally {
      MDC.remove("user");
      NDC.remove();
    }

    assertEquals("No errors expected, got " + errorHandler.size(), 0, errorHandler.size());
    assertEquals(
      "Injected SQL must not be executed, the payloads must be stored verbatim",
      "INFO; alice; first; ctx\n" +
        "WARN; " + mdcPayload + "; second; " + ndcPayload + "\n",
      joinSorted(getMessages()));
  }

  private static String joinSorted(List list) {
    Collections.sort(list);
    StringBuffer sb = new StringBuffer();
    for (Iterator i = list.iterator(); i.hasNext();) {
      sb.append(i.next()).append('\n');
    }
    return sb.toString();
  }

  private List getMessages() throws SQLException {
    List res = new ArrayList();
    PreparedStatement ps = con.prepareStatement("select level,location,message,message2 from logs");
    try {
      ResultSet rs = ps.executeQuery();
      try {
        while (rs.next()) {
          res.add(rs.getString(1) + "; " + rs.getString(2)
                  + "; " + rs.getString(3) + "; " + rs.getString(4));
        }
      } finally {
        rs.close();
      }
    } finally {
      ps.close();
    }
    return res;
  }
}
