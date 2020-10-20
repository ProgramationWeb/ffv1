package com.fatec.scel.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
	@GetMapping("/")
	public String home() {
		return "/paginaMenu";
}
@GetMapping("/aluno/cadastrar")
public String cadastrarAluno() {
	return "/cadastrarAluno";
}
@GetMapping("/livro/cadastrar")
public String cadastrarLivro() {
	return "/cadastrarLivro";
	}
@GetMapping("/login")
public String autenticacao() {
return "/paginaLogin";
}
}	
