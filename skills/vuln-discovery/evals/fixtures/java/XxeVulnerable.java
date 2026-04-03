/**
 * Vulnerable: XXE via DocumentBuilderFactory without secure processing.
 */
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;
import javax.servlet.http.*;

public class XxeVulnerable extends HttpServlet {

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // No secure processing, no disabling of external entities
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(request.getInputStream());
        String name = doc.getElementsByTagName("name").item(0).getTextContent();
        response.getWriter().println("Hello, " + name);
    }
}
