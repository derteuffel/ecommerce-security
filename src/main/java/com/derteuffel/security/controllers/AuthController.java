package com.derteuffel.security.controllers;

import com.derteuffel.security.enums.Role;
import com.derteuffel.security.messages.requests.SignupForm;
import com.derteuffel.security.messages.responses.MessageResponse;
import com.derteuffel.security.models.User;
import com.derteuffel.security.repositories.UserRepository;
import com.derteuffel.security.securities.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.security.Principal;

@Slf4j
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtTokenProvider jwtUtils;


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;



    @GetMapping("/login")
    public ResponseEntity<?> login(Principal principal){
        System.out.println(principal.getName());
        System.out.println("je suis dans la fonction");
        if(principal == null){
            //This should be ok http status because this will be used for logout path.
            return ResponseEntity.ok(principal);
        }
        UsernamePasswordAuthenticationToken authenticationToken = (UsernamePasswordAuthenticationToken) principal;
        System.out.println(authenticationToken.getName());
        User user = userRepository.findByUsernameOrEmail(authenticationToken.getName(),authenticationToken.getName()).get();
        user.setToken(jwtUtils.generateToken(authenticationToken));
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> enregistrerUtilisateur(@Valid @RequestBody SignupForm requete) {
        if (userRepository.existsByUsername(requete.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Nom utilisateur deja utilise!"));
        }

        if (userRepository.existsByEmail(requete.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Email deja utilise!"));
        }

        // Creer un nouveau compte utilisateur
        User user = new User();
        user.setUsername(requete.getUsername());
        user.setEmail(requete.getEmail());
        user.setActive(false);
        user.setPassword(encoder.encode(requete.getPassword()));

        switch (requete.getRole()) {
            case "ADMIN":
                user.setRole(Role.ADMIN);
                break;
            case "SELLER":
                user.setRole(Role.SELLER);
                break;
            case "ENTERPRENER":
                user.setRole(Role.ENTERPRENER);
                break;
            case "ROOT":
                user.setRole(Role.ROOT);
                break;
            default:
                user.setRole(Role.ROOT);
                break;
        }
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Utilisateur enregistre avec success!","succes"));
    }
}
