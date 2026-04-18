package com.example.security.ui.main;

import android.content.Intent;

import androidx.recyclerview.widget.LinearLayoutManager;

import com.example.security.adapter.AlgorithmAdapter;
import com.example.security.base.AlgorithmType;
import com.example.security.data.model.AlgorithmItem;
import com.example.security.databinding.ActivityMainBinding;
import com.example.security.ui.base.BaseCipherActivity;
import com.example.security.ui.cipher.CipherActivity;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends BaseCipherActivity {

    private ActivityMainBinding binding;
    private AlgorithmAdapter    adapter;


    @Override
    protected void initViews() {

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        adapter = new AlgorithmAdapter(buildAlgorithmList(), this::openCipherScreen);
        binding.recyclerViewAlgorithms.setLayoutManager(new LinearLayoutManager(this));
        binding.recyclerViewAlgorithms.setAdapter(adapter);
    }

    @Override
    protected void setupListeners() {
    }


    private List<AlgorithmItem> buildAlgorithmList() {
        List<AlgorithmItem> items = new ArrayList<>();
        items.add(new AlgorithmItem(AlgorithmType.CAESAR,          "Simple shift cipher — great starting point"));
        items.add(new AlgorithmItem(AlgorithmType.MONOALPHABETIC,  "Each letter maps to a unique substitute"));
        items.add(new AlgorithmItem(AlgorithmType.PLAYFAIR,        "Digraph substitution using a 5×5 matrix"));
        items.add(new AlgorithmItem(AlgorithmType.POLYALPHABETIC,  "Vigenère — multiple Caesar ciphers combined"));
        items.add(new AlgorithmItem(AlgorithmType.AUTOKEY,         "Key extends itself using the plaintext"));
        items.add(new AlgorithmItem(AlgorithmType.RAIL_FENCE,      "Transposition across zigzag rails"));
        items.add(new AlgorithmItem(AlgorithmType.DES,             "Symmetric block cipher — 64-bit key"));
        items.add(new AlgorithmItem(AlgorithmType.RSA,             "Asymmetric public-key cryptography"));
        items.add(new AlgorithmItem(AlgorithmType.AES,             "Advanced Encryption Standard — industry grade"));
        return items;
    }

    private void openCipherScreen(AlgorithmItem item) {
        Intent intent = new Intent(this, CipherActivity.class);
        intent.putExtra(CipherActivity.EXTRA_ALGORITHM_TYPE, item.getType().name());
        startActivity(intent);
    }
}