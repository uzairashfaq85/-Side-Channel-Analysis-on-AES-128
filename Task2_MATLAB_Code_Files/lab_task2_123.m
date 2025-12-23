clc;
clear all;
load('attack_data_10k.mat');
load('constants.mat');

% Configuration
mode = 1;
datapoints2 = datapoints * 1000000;
samples = size(datapoints2, 1);
traces = datapoints2(1:samples, :);
trace_length = size(traces, 2);

K = 0:255;

% Define power models
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
results = struct();

fprintf('Comparing %d power models with %d traces...\n\n', num_models, samples);

% Test each power model
for model_idx = 1:num_models
    model_name = power_models{model_idx};
    fprintf('Testing model: %s\n', model_name);
    
    model_key = zeros(1, 16);
    model_correlations = zeros(1, 16);
    model_success_rate = zeros(1, 16);
    all_R = cell(1, 16);
    
    for byte_to_attack = 1:16
        fprintf('  Byte %d/16... ', byte_to_attack);
        
        D = plaintexts_SCA(1:samples, byte_to_attack);
        
        V = zeros(samples, length(K));
        for key_idx = 1:length(K)
            intermediate = bitxor(D, K(key_idx), 'uint8');
            V(:, key_idx) = SubBytes(intermediate + 1);
        end
        
        % Apply power model
        H = zeros(samples, length(K));
        
        if model_idx == 1
            % Hamming Weight model
            for key_idx = 1:length(K)
                H(:, key_idx) = sum(dec2bin(V(:, key_idx), 8) == '1', 2);
            end
        else
            % Single bit model using bitget
            bit_index = model_idx - 2;
            for key_idx = 1:length(K)
                H(:, key_idx) = bitget(V(:, key_idx), bit_index + 1);
            end
        end
        
        correct_key_found_at = samples;
        trace_counts = [100, 500, 1000, 2000, 5000, samples];
        trace_counts = trace_counts(trace_counts <= samples);
        
        for trace_count_idx = 1:length(trace_counts)
            current_traces = trace_counts(trace_count_idx);
            
            R = zeros(length(K), trace_length);
            for key_index = 1:length(K)
                for k = 1:trace_length
                    correlation_matrix = corrcoef(H(1:current_traces, key_index), ...
                                                 traces(1:current_traces, k));
                    R(key_index, k) = correlation_matrix(1, 2);
                end
            end
            
            [M, I] = max(abs(R(:)));
            [key_row, ~] = ind2sub(size(R), I);
            current_key = key_row - 1;
            
            if trace_count_idx == length(trace_counts)
                model_key(byte_to_attack) = current_key;
                model_correlations(byte_to_attack) = M;
                all_R{byte_to_attack} = R;
            elseif correct_key_found_at == samples && current_key == model_key(byte_to_attack)
                correct_key_found_at = current_traces;
            end
        end
        
        model_success_rate(byte_to_attack) = correct_key_found_at;
        fprintf('Key: 0x%02X, Min traces: %d\n', model_key(byte_to_attack), correct_key_found_at);
    end
    
    results(model_idx).name = model_name;
    results(model_idx).recovered_key = model_key;
    results(model_idx).correlations = model_correlations;
    results(model_idx).min_traces_needed = model_success_rate;
    results(model_idx).avg_traces_needed = mean(model_success_rate);
    results(model_idx).all_R = all_R;
    
    fprintf('  Average traces needed: %.1f\n\n', mean(model_success_rate));
end