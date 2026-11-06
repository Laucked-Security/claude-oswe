package com.ex;

public class Dao {
    public void find(java.sql.Connection conn, String q) throws java.sql.SQLException {
        java.sql.Statement st = conn.createStatement();
        st.execute(q);
    }
}
