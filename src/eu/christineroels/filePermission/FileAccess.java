package eu.christineroels.filePermission;

import java.io.File;
import java.io.FilePermission;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class FileAccess {
    List<File> directory = new ArrayList<>();
    public <R> List<R> executeFunction(Function<File,R> func){
        List<R> rList = new ArrayList<>();
        for(File file : directory){
            //We must ensure
            // that the caller only reads a file and
            // is not able to overwrite or delete it
            // irrespective of what level of permission the caller has.

            //Create a permission to "read" for each file (other possibilities: write, delete)
            Permission perm = new FilePermission(file.getPath(), "read");
            PermissionCollection permissionCollection = perm.newPermissionCollection();
            permissionCollection.add(perm);

            //Adding an element to a list is an action that does not return something but there is a permission
            //granted on each files so we need an access controller + doPrivileged(lambda exp. action, AccessControlContext(ProtectionDomain[] p) a)

            //This checks whether the caller has permission to do whatever it is trying to do in the function.
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                //Add whatever results of a function applied to each file from the directory, to a list
                rList.add(func.apply(file));
                return null;
            },
            //By applying a new AccessControlContext with just the read permission, it ensures that even if the caller
            //has full permissions, it is restricted to performing only the read operation.
             new AccessControlContext(
                    new ProtectionDomain[]{
                    new ProtectionDomain(null, permissionCollection)
            })
            );


        }
        return rList;
    }
}
