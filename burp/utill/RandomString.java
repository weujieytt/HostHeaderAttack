package burp.utill;

import java.util.Random;

public class RandomString {
    public RandomString() {
    }

    public static String randomHost(Integer length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();

        for(int i = 0; i < length; ++i) {
            int number = random.nextInt(62);
            sb.append(str.charAt(number));
        }

        return sb + ".com";
    }

    public static void printArray(String message, int[] array) {
        System.out.println(message + ": [length = " + array.length + "]");

        for(int i = 0; i < array.length; ++i) {
            if (i != 0) {
                System.out.print(", ");
            }

            System.out.print(array[i]);
        }

        System.out.println();
    }
}
