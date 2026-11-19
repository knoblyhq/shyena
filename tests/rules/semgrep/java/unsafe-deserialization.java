package com.example.demo;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.thoughtworks.xstream.XStream;
import java.beans.XMLDecoder;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class Deser {

    Object read(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: shyena.java.unsafe-deserialization
        return ois.readObject();
    }

    Object readFiltered(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.*;!*"));
        // ok: shyena.java.unsafe-deserialization
        return ois.readObject();
    }

    Object xml(InputStream in) {
        // ruleid: shyena.java.unsafe-deserialization
        return new XMLDecoder(in).readObject();
    }

    Object xstream(String xml) {
        XStream x = new XStream();
        // ruleid: shyena.java.unsafe-deserialization
        return x.fromXML(xml);
    }

    Object xstreamAllowed(String xml) {
        XStream x = new XStream();
        x.allowTypes(new Class[] {Deser.class});
        // ok: shyena.java.unsafe-deserialization
        return x.fromXML(xml);
    }

    ObjectMapper mapper() {
        ObjectMapper m = new ObjectMapper();
        // ruleid: shyena.java.jackson-polymorphic-typing
        m.enableDefaultTyping();
        // ruleid: shyena.java.jackson-polymorphic-typing
        m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
        // ok: shyena.java.jackson-polymorphic-typing
        m.activateDefaultTyping(myValidator(), ObjectMapper.DefaultTyping.NON_FINAL);
        return m;
    }

    // ruleid: shyena.java.jackson-polymorphic-typing
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, property = "@class")
    static abstract class Payload {}

    // ok: shyena.java.jackson-polymorphic-typing
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
    static abstract class Shape {}
}
