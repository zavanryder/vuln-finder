/**
 * Safe: SQL injection -- parameterized PreparedStatement.
 */
import java.sql.*;
import javax.servlet.http.*;

public class SqliSafe extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String username = request.getParameter("username");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app");
        PreparedStatement stmt = conn.prepareStatement(
            "SELECT * FROM users WHERE username = ?"
        );
        stmt.setString(1, username);
        ResultSet rs = stmt.executeQuery();
        while (rs.next()) {
            response.getWriter().println(rs.getString("email"));
        }
    }
}
