package com.derteuffel.security.services;

import com.derteuffel.security.interfaces.UserInterface;
import com.derteuffel.security.models.User;
import com.derteuffel.security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserServiceImpl implements UserInterface {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Override
    public User saveUser(User user) {

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public User findByUsenameOrEmail(String username, String email) {
        return userRepository.findByUsernameOrEmail(username, email).orElse(null);
    }

    @Override
    public void activeUser(String code) {
        User user = userRepository.findByCode(code);
        user.setActive(true);
        userRepository.save(user);

    }

    @Override
    public void deleteUser(Long id) {

        User user = userRepository.getOne(id);
        userRepository.delete(user);
    }

    @Override
    public void desactiveUser(Long id) {

        User user = userRepository.getOne(id);
        user.setActive(false);
        userRepository.save(user);
    }
}
