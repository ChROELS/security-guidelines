package eu.christineroels.passwordAuthentification;

import java.util.regex.Pattern;

public class UserPasswordValidation {

    private String password;
    private final String regex =
            "^"//Start of the string
                    +"(?=.*[a-z])"//min. a letter between a-z
        +"(?=.*[0-9])"+ //min. a number between 0-9
            "(?=.*[A-Z])"+ //min. a letter between A-Z
            "(?=.*[@#$%^&+=()])"+ //min. a special character
        ".{12,20}"//min. between 12 and 20 characters
                    +"$"; //End of the string

    public Boolean isValid(String password){
        Boolean response;
        //Step to create a matcher expression that will be compared to the password
        Pattern compiledRegex = Pattern.compile(this.regex);
        if(password==null){
            response = null;
        }else{
            //if the password succeeds...matches() returns a boolean
            response= compiledRegex.matcher(password).matches();
        }
        return response;
    }

    public String explainInvalid(String password){
        if(!isValid(password)) {
            if (password.length() < 12 || password.length() > 20) {
                return "The password should contain between 12 and 20 characters";
            } else {
                return "The password is long enough but it should also contain at least a letter, " +
                        "a capital letter " + ", a number and a special character among @#$%^&+=()";
            }
        }else{
            return "Password is valid";
        }
    }

    public static void main(String[] args) {
        UserPasswordValidation userPasswordValidation = new UserPasswordValidation();
        Boolean test1 = userPasswordValidation.isValid("azer5@TRE");
        System.out.println(test1);
        System.out.println(userPasswordValidation.explainInvalid("azer5@TRE"));
        Boolean test2 = userPasswordValidation.isValid("azer5@TRE0123");
        System.out.println(test2);
        System.out.println(userPasswordValidation.explainInvalid("azer5@TRE0123"));
    }
}
