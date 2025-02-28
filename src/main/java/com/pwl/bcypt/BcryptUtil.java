package com.pwl.bcypt;

import org.mindrot.jbcrypt.BCrypt;

public class BcryptUtil {
    public static boolean checkPassword(String plainTextPassword, String hashedPassword) {
        return BCrypt.checkpw(plainTextPassword, hashedPassword);
    }
}
