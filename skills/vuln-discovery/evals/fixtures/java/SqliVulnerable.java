/**
 * Vulnerable: SQL injection via string concatenation in Statement.
 */
import java.sql.*;
import javax.servlet.http.*;

public class SqliVulnerable extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String username = request.getParameter("username");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE username = '" + username + "'"
        );
        while (rs.next()) {
            response.getWriter().println(rs.getString("email"));
        }
    }
}
