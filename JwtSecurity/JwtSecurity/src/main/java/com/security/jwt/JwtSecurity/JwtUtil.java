package com.security.jwt.JwtSecurity;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
@Service
public class JwtUtil {

	private String SECRET_KEY = "secret";

	// FLOW A
//1.First method being called is a generate toekn which calls the create token
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userDetails.getUsername());
	}

//2.This method will take your claims and the username an dwill egnerate the token out of it.
	private String createToken(Map<String, Object> claims, String subject) {

		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
				.signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
	}

	// FLOW B
//gets the username and then validate the token and also check token is not expired
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	// takes a token and return user name
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	// it takes in a token and uses claims resolver in order to figure out what the
	// claims are
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	private Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
	}

//takes a token and returns the expiration date
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	

//returns whether toekn is expired or not
	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}
}
