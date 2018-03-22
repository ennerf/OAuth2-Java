package us.hebi.oauth2.server;

import java.util.Optional;
import java.util.function.Function;

/**
 * @author Florian Enner < florian @ hebirobotics.com >
 * @since 22 Mar 2018
 */
public class OptionalUtils {

    public static <T, R> Function<T, Optional<R>> errorAsEmpty(FunctionWithException<T, R> source) {
        return input -> {
            try {
                return Optional.ofNullable(source.apply(input));
            } catch (Exception e) {
                return Optional.empty();
            }
        };
    }

    @FunctionalInterface
    public interface FunctionWithException<T, R> {

        /**
         * Applies this function to the given argument.
         *
         * @param t the function argument
         * @return the function result
         */
        R apply(T t) throws Exception;

    }
}
