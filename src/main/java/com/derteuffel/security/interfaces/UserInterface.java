package com.derteuffel.security.interfaces;

import com.derteuffel.security.models.User;

public interface UserInterface {

    User saveUser(User user);
    User findByUsenameOrEmail(String username, String email);
    void activeUser(String code);
    void deleteUser(Long id);
    void desactiveUser(Long id);
}
