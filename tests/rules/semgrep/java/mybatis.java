package com.example.demo;

import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

@Mapper
public interface OrderMapper {

    // ruleid: shyena.java.mybatis-annotation-dollar-substitution
    @Select("SELECT * FROM orders WHERE customer = '${customer}'")
    List<Order> byCustomer(@Param("customer") String customer);

    // ok: shyena.java.mybatis-annotation-dollar-substitution
    @Select("SELECT * FROM orders WHERE customer = #{customer}")
    List<Order> byCustomerSafe(@Param("customer") String customer);

    // ruleid: shyena.java.mybatis-annotation-dollar-substitution
    @Update("UPDATE orders SET status = #{status} ORDER BY ${sort}")
    int touch(@Param("status") String status, @Param("sort") String sort);
}
