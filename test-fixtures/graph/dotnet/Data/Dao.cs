namespace Demo.Data;

using System.Data.SqlClient;

public class Dao
{
    public void Find(SqlConnection conn, string q)
    {
        var cmd = new SqlCommand(q, conn);
        cmd.ExecuteReader();
    }
}
