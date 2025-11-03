package ishop.service;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.json.simple.JSONObject;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@WebServlet("/Logins")
public class Logins extends HttpServlet {
	private static final long serialVersionUID = 1L;

	public Logins() { }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String password = request.getParameter("password");
		String username = request.getParameter("username");

		// basic null checks
		if (username == null || password == null) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}

		// email validation
		boolean isEmail = username.matches("^\\w+[\\.]*\\w+@([\\w-]+\\.)+[\\w-]{2,4}$");
		if (!isEmail) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		// JNDI lookup for DataSource (requires context.xml + resource-ref in web.xml)
		DataSource ds;
		try {
			InitialContext ctx = new InitialContext();
			ds = (DataSource) ctx.lookup("java:comp/env/jdbc/ishope");
			if (ds == null) {
				throw new NamingException("DataSource jdbc/ishope not found");
			}
		} catch (NamingException ne) {
			throw new ServletException("JNDI lookup failed for jdbc/ishope", ne);
		}

		String sql = "SELECT id, firstname, lastname, password FROM public.users WHERE email = ?";

		try (Connection conn = ds.getConnection();
			 PreparedStatement ps = conn.prepareStatement(sql)) {

			ps.setString(1, username);
			try (ResultSet rs = ps.executeQuery()) {
				if (!rs.next()) {
					// user not found
					response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
					return;
				}

				String storedHash = rs.getString("password"); // get hashed password from DB
				boolean matched;
				try {
					matched = SecurePassword.validatePassword(password, storedHash);
				} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
					// treat validation errors as auth failure but log server-side
					e.printStackTrace();
					response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
					return;
				}

				if (!matched) {
					response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
					return;
				}

				// success: build JSON response
				String id = String.valueOf(rs.getInt("id"));
				String firstname = rs.getString("firstname");
				String lastname = rs.getString("lastname");
				String fullname = (firstname == null ? "" : firstname) + " " + (lastname == null ? "" : lastname);

				HttpSession session = request.getSession(true);
				// Optional: set secure flags at container level (Tomcat) or via headers if needed

				response.setContentType("application/json;charset=UTF-8");
				String json = "{\n";
				json += "\"user\": \"" + JSONObject.escape(username) + "\",\n";
				json += "\"fullname\": \"" + JSONObject.escape(fullname.trim()) + "\",\n";
				json += "\"usertype\": \"client\",\n";
				json += "\"iduser\": " + id + ",\n";
				json += "\"token\": \"" + JSONObject.escape(session.getId()) + "\"\n";
				json += "}";

				response.getWriter().println(json);
			}

		} catch (Exception e) {
			// DB or other unexpected error -> 500
			e.printStackTrace();
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
	}
}