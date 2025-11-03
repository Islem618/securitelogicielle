package ishop.service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;


import java.util.ArrayList;


public class DataServices {
	
	private Connection Facts = null;
	private Statement pStatement = null;
		
	public  DataServices ()
	{}
	
	
	
	public Connection databaseConnection (String dbName)
	{
		String DataBase = dbName.toLowerCase();
		try {
			Class.forName("org.postgresql.Driver");
			Facts = DriverManager.getConnection("jdbc:postgresql://localhost:5432/"+ DataBase +"?user=postgres&password=postgres");
         	if (Facts != null)
         	{
         		System.out.println("databaseConnection: Connection established to " + DataBase + " database.");
         		return Facts;
         	}
         	else
         	{
         		System.out.println("databaseConnection: Connection failed to " + DataBase + " database.");
         		return null;
         	}
		} catch (Exception e)
		{
         System.out.println ("databaseConnection: Bloc exception : " + e.getMessage());
         e.printStackTrace();
         return null;
		}
	}
		
		
	//execute a given query
	public ArrayList <ArrayList <String>>  doQuery (String dbase, String sql)
	{
	   try {
	       Connection connect = this.databaseConnection(dbase); 
	       
		   pStatement =  connect.createStatement();
		   
	       ResultSet rs = pStatement.executeQuery(sql);

	       System.out.println("dataService.doQuery : Execution of the query : " + sql + "\n");
	       int nb = rs.getMetaData().getColumnCount();
	       
	       ArrayList <String> clmName = new ArrayList <String> ();
	       for (int i = 1; i <= nb; i ++)
	       {
	    	   clmName.add(rs.getMetaData().getColumnName(i).toUpperCase());
	       }
	      
	       
	       ArrayList <ArrayList <String>> result = new ArrayList <ArrayList <String>> ();
	       result.add(clmName);
	       
	      
	       ArrayList <String> t = new   ArrayList <String> ();
	       if (rs.next ())
	       {
	    	   for (int i = 1; i <= nb ; i ++)
	    	   {
	    		   t.add(rs.getString(i));
	    	   } 
	    	  
	    	   result.add(t);
	       }

	       while (rs.next()) {
	    	   //serialize the tuple execpt score1 and score2 columns
	    	   t = new   ArrayList <String> ();
	    	   for (int i = 1; i <= nb ; i ++)
	    	   {
	    		   t.add(rs.getString(i));
	    	   }
	    	   
	    	   result.add(t);
	       }
	            
	       connect.close();
	       pStatement.close();
	       rs.close();
	       return result;     
	   } catch (Exception e)
	   		{
		   System.out.println(sql);		
		   System.out.println ("doQuery(): Bloc exception: " + e.getMessage());
	       		return null;
	   		}
	 }

	
}

