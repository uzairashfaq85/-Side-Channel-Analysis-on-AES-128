% =============================================================================
% File    : lab_task2_123.m
% Project : Side-Channel Analysis on AES-128
% Author  : Uzair Ashfaq
% Created : November 2025
% Purpose : DPA / CPA attack on AES-128 comparing nine different power models.
%           Loads 10 000 captured power traces and their plaintexts, iterates
%           over every key byte (0-15), and for each key byte evaluates:
%             - Hamming Weight leakage model
%             - Single-bit leakage models for bits 0-7
%           Determines the minimum number of traces required to recover the
%           correct key byte for each model and reports average efficiency.
% =============================================================================

clc;
clear all;
load('attack_data_10k.mat');
load('constants.mat');

% Scale raw ADC counts to micro-volts (matches oscilloscope full-scale)
datapoints2 = datapoints * 1000000;
samples     = size(datapoints2, 1);   % number of traces
traces      = datapoints2(1:samples, :);
trace_length = size(traces, 2);       % samples per trace

K = 0:255;   % all 256 key-byte hypotheses

% ------------------------------------------------------------------
% Power models to evaluate
% ------------------------------------------------------------------
power_models = {
    'Hamming Weight',
    'Bit 0 (LSB)',
    'Bit 1',
    'Bit 2',
    'Bit 3',
    'Bit 4',
    'Bit 5',
    'Bit 6',
    'Bit 7 (MSB)'
};

num_models = length(power_models);
results    = struct();

fprintf('Comparing %d power models with %d traces...\n\n', num_models, samples);

% ------------------------------------------------------------------
% Main loop: one iteration per power model
% ------------------------------------------------------------------
for model_idx = 1:num_models
    model_name = power_models{model_idx};
    fprintf('Testing model: %s\n', model_name);

    model_key          = zeros(1, 16, 'uint8');
    model_correlations = zeros(1, 16);
    model_success_rate = zeros(1, 16);
    all_R              = cell(1, 16);

    for byte_to_attack = 1:16
        fprintf('  Byte %d/16... ', byte_to_attack);

        D = plaintexts_SCA(1:samples, byte_to_attack);  % plaintext column

        % ----------------------------------------------------------
        % Compute intermediate values: V = SubBytes(D XOR K)
        % ----------------------------------------------------------
        V = zeros(samples, length(K), 'uint8');
        for key_idx = 1:length(K)
            intermediate     = bitxor(D, uint8(K(key_idx)));
            V(:, key_idx)    = SubBytes(double(intermediate) + 1);
        end

        % ----------------------------------------------------------
        % Build hypothetical power matrix H (samples x 256)
        % ----------------------------------------------------------
        H = zeros(samples, length(K));

        if model_idx == 1
            % Hamming Weight: count set bits in each intermediate value
            for key_idx = 1:length(K)
                H(:, key_idx) = sum(dec2bin(double(V(:, key_idx)), 8) == '1', 2);
            end
        else
            % Single-bit model: extract one bit (bit positions are 1-based in bitget)
            % model_idx==2 -> bit 1 (LSB), model_idx==3 -> bit 2, ..., model_idx==9 -> bit 8 (MSB)
            bit_position = model_idx - 1;   % maps 2->1, 3->2, ..., 9->8
            for key_idx = 1:length(K)
                H(:, key_idx) = double(bitget(V(:, key_idx), bit_position));
            end
        end

        % ----------------------------------------------------------
        % Step 1: compute correlation with ALL traces to get the
        %         true key byte first, then check smaller sets.
        % ----------------------------------------------------------
        trace_counts = [100, 500, 1000, 2000, 5000, samples];
        trace_counts = trace_counts(trace_counts <= samples);

        % Determine true key using the full trace set (last entry)
        R_full = zeros(length(K), trace_length);
        n_full = trace_counts(end);
        for key_index = 1:length(K)
            for k = 1:trace_length
                cm = corrcoef(H(1:n_full, key_index), traces(1:n_full, k));
                R_full(key_index, k) = cm(1, 2);
            end
        end
        [M_full, I_full]          = max(abs(R_full(:)));
        [key_row_full, ~]         = ind2sub(size(R_full), I_full);
        true_key                  = key_row_full - 1;  % 0-based key byte
        model_key(byte_to_attack) = uint8(true_key);
        model_correlations(byte_to_attack) = M_full;
        all_R{byte_to_attack}     = R_full;

        % ----------------------------------------------------------
        % Step 2: find the minimum number of traces that already
        %         recovers the same key byte as the full-set attack.
        % ----------------------------------------------------------
        correct_key_found_at = samples;   % default: needs all traces
        for trace_count_idx = 1:(length(trace_counts) - 1)
            current_traces = trace_counts(trace_count_idx);
            R_sub = zeros(length(K), trace_length);
            for key_index = 1:length(K)
                for k = 1:trace_length
                    cm = corrcoef(H(1:current_traces, key_index), ...
                                  traces(1:current_traces, k));
                    R_sub(key_index, k) = cm(1, 2);
                end
            end
            [~, I_sub]     = max(abs(R_sub(:)));
            [key_row_sub, ~] = ind2sub(size(R_sub), I_sub);
            current_key    = key_row_sub - 1;

            if current_key == true_key
                correct_key_found_at = current_traces;
                break;   % stop at the first (smallest) count that works
            end
        end

        model_success_rate(byte_to_attack) = correct_key_found_at;
        fprintf('Key: 0x%02X, Min traces: %d\n', true_key, correct_key_found_at);
    end

    results(model_idx).name             = model_name;
    results(model_idx).recovered_key    = model_key;
    results(model_idx).correlations     = model_correlations;
    results(model_idx).min_traces_needed = model_success_rate;
    results(model_idx).avg_traces_needed = mean(model_success_rate);
    results(model_idx).all_R            = all_R;

    fprintf('  Average traces needed: %.1f\n\n', mean(model_success_rate));
end