package eu.christineroels.passwordAuthentification;

import java.security.NoSuchAlgorithmException;

import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.TreeMap;

public class UserPasswordRecognition {
    private UserPasswordEncryption encryption;
    private Map<String,String> mockDatabase;

    public UserPasswordRecognition(String userPassword) {
        this.encryption = new UserPasswordEncryption(userPassword);
        this.mockDatabase = new TreeMap<>();
    }

    public String scrambleUserPassword(String password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException{
        String encryptedPassword;
        byte[] encryptionMessage = encryption.PBKDF2userPassword(salt,password);
        encryptedPassword = encryption.bytesToHexadecimal(encryptionMessage);
        return encryptedPassword;
    }

    public void saveNewLogin(String userName, String encryptedPassword)  {
        if(userName!= null && !mockDatabase.containsKey(userName)){
            mockDatabase.put(userName, encryptedPassword);
        }
    }

    public String getSavedPassword(String userName){
        if(mockDatabase.containsKey(userName)){
            return mockDatabase.get(userName);
        }
        return null;
    }

    public Boolean recognize(String userName, String password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String encryptedPassword = scrambleUserPassword(password,salt);
        System.out.println(encryptedPassword);
        System.out.println(getSavedPassword(userName));
        return encryptedPassword.equals(getSavedPassword(userName));
    }

    public static void main(String[] args) {
        UserPasswordRecognition userPasswordRecognition = new UserPasswordRecognition("azer5@TRE0123");
        try {
            //Step 1: create a personal array of random numbers that should be retrieved later
            //We can save it in a database table along with the userName and the scrambled version of the password
            byte[] salt = userPasswordRecognition.encryption.getSalt();
            //Step 2: scramble the password
            String scrambled = userPasswordRecognition.scrambleUserPassword("azer5@TRE0123",salt);
            //Step 3: save the username and the scrambled version of the password in the database
            userPasswordRecognition.saveNewLogin("chris",scrambled);
            //Step 4: The user will enter a name and a plain password. if, 'with the same amount of salt',
            //the password internally scrambled at the time of login 'taste perfectly like' the scrambled version saved
            //in the database, the password has been recognized. We compare the scrambled versions of a plain password
            //only the end user knows its plain password
            System.out.println(userPasswordRecognition.recognize("chris","azer5@TRE0123",salt));
        }catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            e.printStackTrace();
        }
    }
}
