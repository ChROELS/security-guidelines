package eu.christineroels.preventingSQLInjection;

import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * prepared statements with the question mark placeholder (“?”)
 * in our queries whenever we need to insert a user-supplied value.
 */
@SuppressWarnings("ALL")
public class CustomerDAO {


    public List<String> customerListByName(String name){
        List<String> list = new ArrayList<>();
        String query =
                "SELECT username, email, password, saltKey" +
                        "FROM Customers WHERE name = ?";
        try(
            Connection connection = DriverManager.getConnection("url","user","password");
                    PreparedStatement preparedStatement = connection.prepareStatement(query)){
                preparedStatement.setString(1, name);
                ResultSet resultSet = preparedStatement.executeQuery();
                resultSet.beforeFirst();
                while(resultSet.next()){
                    String userName = resultSet.getString(2);
                    String userEmail = resultSet.getString(3);
                    String userPassword = resultSet.getString(4);
                    byte[] userSalt = resultSet.getBytes(5);
                    list.add(String.format("%s %s %s %s",userName,userEmail,userPassword, Arrays.toString(userSalt)));
                }
            }catch(Exception e){
            e.printStackTrace();
        }
        return list;
    }
    public List<String> customerListByNameWithJpa(String name){
        List<String> list = new ArrayList<>();
        String query =
                "SELECT username, email, password, saltKey" +
                        "FROM Customers WHERE name = :name";
        //if we are using JPA: best to use handle the type in the code with a TypedQuery
        try{
            //TypedQuery<String> q = entityManager.createQuery(query,String.class)
            //        .setParameter("name",name);
            //Execution of the query
            //...
        }catch(Exception e){
            e.printStackTrace();
        }
        return list;
    }
    public String customerName(String id) {
        String query = "SELECT username" +
                "FROM Customers WHERE id = ?";
        try (
                Connection connection = DriverManager.getConnection("url", "user", "password");
                PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            //Additional protection is to handle the dataType: The user will input a String representation
            //of their id but in the database, it is saved as an Integer. The parsing will not work
            //if the user try to enter characters that can not be parsed to Integer values
            preparedStatement.setInt(1, Integer.parseInt(id));
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return null;
    }
}
