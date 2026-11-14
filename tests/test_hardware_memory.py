from satsuma.hardware_memory import assess


def test_cpu_feature_and_boot_request_are_not_activation_proof():
    result = assess('model name : AMD fixture\nflags : sme sev\n', 'quiet mem_encrypt=on')
    assert result['status'] == 'ACTIVATION_UNVERIFIED'
    assert result['cpu_features'] == ['sev', 'sme']
    assert result['kernel_request'] == ['mem_encrypt=on']
    assert not result['all_ram_encrypted_verified']


def test_explicit_kernel_activation_is_distinct_from_total_ram_claim():
    result = assess('flags : sme\n', kernel_log='[0.5] Memory Encryption Features active: SME\n')
    assert result['status'] == 'SME_ACTIVE_REPORTED_BY_KERNEL'
    assert not result['all_ram_encrypted_verified']


def test_capability_log_is_not_activation():
    result = assess('flags : sme\n', kernel_log='AMD supports SME\nMemory Encryption Features active: SEV\n')
    assert result['status'] == 'ACTIVATION_UNVERIFIED'
