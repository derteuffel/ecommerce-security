package com.derteuffel.security.controllers;

import com.derteuffel.security.enums.Role;
import com.derteuffel.security.messages.requests.SignupForm;
import com.derteuffel.security.messages.responses.MessageResponse;
import com.derteuffel.security.models.User;
import com.derteuffel.security.repositories.UserRepository;
import com.derteuffel.security.securities.JwtTokenProvider;
import com.derteuffel.security.utils.UtilsService;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

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
    public ResponseEntity<?> login(@RequestHeader("Authorization") String basic){
        
        String[] cridentials = UtilsService.extractCredentials(basic);
        Map<String, Object> output = new HashMap();
        if(cridentials == null || cridentials.length!=2){
            output.put("status", 400);
            output.put("message", "Invalid inputs");
            return new ResponseEntity(output, HttpStatus.BAD_REQUEST);
        }
            
        String username = cridentials[0];
        String password = cridentials[1];
        
        Optional<User> userOptional = userRepository.findByUsernameOrEmail(username, username);
        if(userOptional.isPresent()){
            User user = userOptional.get();
            if(encoder.matches(password, user.getPassword())){
                user.setPassword(null);
                user.setToken(jwtUtils.generateToken(user));
                return new ResponseEntity(user, HttpStatus.OK);
            }
        }
        
        output.put("status", "401");
        output.put("message", "Invalid credentials");
        return new ResponseEntity(output, HttpStatus.UNAUTHORIZED);
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
