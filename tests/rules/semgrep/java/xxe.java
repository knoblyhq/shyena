package com.example.demo;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;

public class Xml {

    void unsafe() throws Exception {
        // ruleid: shyena.java.xxe
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder();
    }

    void safe() throws Exception {
        // ok: shyena.java.xxe
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder();
    }

    void sax() throws Exception {
        // ruleid: shyena.java.xxe
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.newSAXParser();
    }

    void stax() {
        // ruleid: shyena.java.xxe
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.createXMLStreamReader(System.in);
    }

    void staxSafe() throws Exception {
        // ok: shyena.java.xxe
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xif.createXMLStreamReader(System.in);
    }
}
