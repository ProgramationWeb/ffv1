package com.fatec.scel;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.junit4.SpringRunner;

import com.fatec.scel.controller.HomeController;

@RunWith(SpringRunner.class)
@WebMvcTest(HomeController.class)
class TesteHomeController {

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void testHomePage() throws Exception {
		mockMvc.perform(get("/"))
		.andExpect(status().isOk())
		.andExpect(view().name("/paginaMenu"));	
	}
	@Test
	public void testCadastraraluno() throws Exception {
		mockMvc.perform(get("/aluno/cadastrar"))
		.andExpect(status().isOk())
		.andExpect(view().name("/cadastrarAluno"));
		
	}
	@Test
	public void testCadastrarLivrio() throws Exception {
		mockMvc.perform(get("/livro/cadastrar"))
		.andExpect(status().isOk())
		.andExpect(view().name("/cadastrarLivro"));
	}
}