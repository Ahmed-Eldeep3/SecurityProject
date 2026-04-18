package com.example.security.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.security.R;
import com.example.security.data.model.AlgorithmItem;
import com.example.security.databinding.ItemAlgorithmBinding;

import java.util.List;

public class AlgorithmAdapter extends RecyclerView.Adapter<AlgorithmAdapter.AlgorithmViewHolder> {

    // ── Callback interface (Interface Segregation) ────────────────────────────
    public interface OnAlgorithmClickListener {
        void onAlgorithmClick(AlgorithmItem item);
    }

    private final List<AlgorithmItem> items;
    private final OnAlgorithmClickListener listener;

    public AlgorithmAdapter(List<AlgorithmItem> items, OnAlgorithmClickListener listener) {
        this.items    = items;
        this.listener = listener;
    }

    // ── RecyclerView lifecycle ────────────────────────────────────────────────

    @NonNull
    @Override
    public AlgorithmViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
        ItemAlgorithmBinding binding = ItemAlgorithmBinding.inflate(inflater, parent, false);
        return new AlgorithmViewHolder(binding);

    }

    @Override
    public void onBindViewHolder(@NonNull AlgorithmViewHolder holder, int position) {
        holder.bind(items.get(position), listener);
    }

    @Override
    public int getItemCount() { return items.size(); }


   public static class AlgorithmViewHolder extends RecyclerView.ViewHolder {

        private ItemAlgorithmBinding binding;

       public AlgorithmViewHolder(@NonNull ItemAlgorithmBinding binding) {
           super(binding.getRoot());
           this.binding = binding;

       }

       void bind(AlgorithmItem item, OnAlgorithmClickListener listener) {
            binding.tvAlgorithmName.setText(item.getName());
            binding.tvAlgorithmDescription.setText(item.getDescription());
            itemView.setOnClickListener(v -> listener.onAlgorithmClick(item));
        }
    }
}
