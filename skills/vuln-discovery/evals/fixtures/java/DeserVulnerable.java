/**
 * Vulnerable: Insecure deserialization via ObjectInputStream on untrusted data.
 */
import java.io.*;
import javax.servlet.http.*;

public class DeserVulnerable extends HttpServlet {

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        Object obj = ois.readObject();
        response.getWriter().println("Received: " + obj.toString());
    }
}
