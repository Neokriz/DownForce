# db_bench에서 DownForce 옵션 사용하기

## 개요
db_bench에 DownForce 관련 옵션들이 명령줄 플래그로 추가되었습니다.

## 사용 가능한 옵션들

### 1. `--enable_downforce_compaction` (NEW)
**타입**: bool  
**기본값**: false  
**설명**: DownForce 압축 전략 활성화. Level 1 파일 선택 로직 변경 및 동시 L0 압축 허용

```bash
--enable_downforce_compaction=true
```

### 2. `--in_memory_merge`
**타입**: bool  
**기본값**: true  
**설명**: 메모리 내 병합 활성화 (플러시 전 memtable 병합)

```bash
--in_memory_merge=true
```

### 3. `--disable_intra_l0_compaction`
**타입**: bool  
**기본값**: false  
**설명**: L0 내부 압축 비활성화

```bash
--disable_intra_l0_compaction=false
```

### 4. `--l0_size_based_stop`
**타입**: bool  
**기본값**: false  
**설명**: 파일 개수 대신 L0 크기 기반 쓰기 중지 트리거 사용

```bash
--l0_size_based_stop=true
```

## 사용 예시

### 기본 벤치마크 (DownForce 비활성화)
```bash
./db_bench \
  --benchmarks="fillrandom,stats" \
  --num=10000000 \
  --compression_type=none \
  --write_buffer_size=67108864 \
  --target_file_size_base=67108864
```

### DownForce 활성화 벤치마크
```bash
./db_bench \
  --benchmarks="fillrandom,stats" \
  --num=10000000 \
  --compression_type=none \
  --write_buffer_size=67108864 \
  --target_file_size_base=67108864 \
  --enable_downforce_compaction=true \
  --in_memory_merge=true \
  --disable_intra_l0_compaction=false \
  --l0_size_based_stop=true
```

### DownForce 전체 옵션 세트
```bash
./db_bench \
  --benchmarks="fillrandom,readrandom,stats" \
  --db=/path/to/db \
  --num=100000000 \
  --threads=16 \
  --compression_type=snappy \
  --write_buffer_size=134217728 \
  --max_write_buffer_number=4 \
  --target_file_size_base=134217728 \
  --max_bytes_for_level_base=536870912 \
  --level0_file_num_compaction_trigger=4 \
  --level0_slowdown_writes_trigger=20 \
  --level0_stop_writes_trigger=30 \
  --enable_downforce_compaction=true \
  --in_memory_merge=true \
  --l0_size_based_stop=true \
  --disable_auto_compactions=false \
  --stats_interval_seconds=10
```

### YCSB 워크로드 A (Read-Heavy with DownForce)
```bash
./db_bench \
  --benchmarks="ycsba" \
  --db=/path/to/db \
  --num=50000000 \
  --threads=8 \
  --enable_downforce_compaction=true \
  --in_memory_merge=true \
  --l0_size_based_stop=true
```

### YCSB 워크로드 B (Write-Heavy with DownForce)
```bash
./db_bench \
  --benchmarks="ycsbb" \
  --db=/path/to/db \
  --num=50000000 \
  --threads=8 \
  --enable_downforce_compaction=true \
  --in_memory_merge=true \
  --l0_size_based_stop=true \
  --write_buffer_size=134217728
```

## 옵션 조합 권장사항

### DownForce 최적 설정 (Write-Heavy 워크로드)
```bash
--enable_downforce_compaction=true
--in_memory_merge=true
--l0_size_based_stop=true
--disable_intra_l0_compaction=false
```

**설명**: 
- DownForce 압축 전략으로 write amplification 감소
- 메모리 내 병합으로 L0 파일 수 감소
- 크기 기반 쓰기 중지로 더 정확한 백프레셔
- 인트라 L0 압축은 DownForce에서 자동으로 제어됨

### 전통적 RocksDB 설정 (비교용)
```bash
--enable_downforce_compaction=false
--in_memory_merge=true
--l0_size_based_stop=false
--disable_intra_l0_compaction=false
```

**설명**: 
- 기본 RocksDB 압축 전략
- 모든 DownForce 최적화 비활성화

## 성능 측정

### 통계 확인
벤치마크 실행 중 실시간 통계를 확인하려면:
```bash
--stats_interval_seconds=10
--statistics=true
```

### 압축 통계 확인
```bash
--benchmarks="fillrandom,stats"
```

stats 벤치마크는 다음 정보를 출력합니다:
- 레벨별 파일 수
- 레벨별 총 크기
- Write amplification
- 압축 통계

### 상세 로그
```bash
--stats_dump_period_sec=600
--max_log_file_size=104857600
```

## 빌드 방법

```bash
cd /home/dccmoon/yhh/DownForce_extension_workspace/DownForce_mod_space
make clean
make db_bench -j$(nproc)
```

## 도움말 확인

모든 사용 가능한 옵션을 보려면:
```bash
./db_bench --help | grep -i downforce
./db_bench --help | grep -i "memory_merge\|intra_l0\|l0_size"
```

## 결과 분석

### Write Amplification 비교
```bash
# DownForce 활성화
./db_bench --benchmarks="fillrandom,stats" --enable_downforce_compaction=true > downforce_results.txt

# DownForce 비활성화  
./db_bench --benchmarks="fillrandom,stats" --enable_downforce_compaction=false > baseline_results.txt

# Write amp 비교
grep "Cumulative writes" downforce_results.txt baseline_results.txt
```

### 압축 시간 비교
```bash
grep "Cumulative compaction" downforce_results.txt baseline_results.txt
```

## 주의사항

1. **메모리 사용량**: DownForce는 더 많은 동시 압축을 허용하므로 메모리 사용량이 증가할 수 있습니다.

2. **디스크 I/O**: 초기에는 압축 I/O가 증가할 수 있지만, 장기적으로는 write amp가 감소합니다.

3. **워크로드 특성**: Write-heavy 워크로드에서 가장 큰 이점을 얻을 수 있습니다.

4. **디버그 모드**: 성능 측정 시 반드시 릴리스 빌드를 사용하세요:
   ```bash
   make clean
   DEBUG_LEVEL=0 make db_bench -j$(nproc)
   ```

## 트러블슈팅

### db_bench 실행 오류
```bash
# 권한 확인
chmod +x db_bench

# 라이브러리 경로 확인
ldd db_bench

# LD_LIBRARY_PATH 설정 (필요시)
export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
./db_bench --help
```

### 옵션이 적용되지 않는 경우
```bash
# 옵션 로그 확인
./db_bench --benchmarks="fillrandom" --enable_downforce_compaction=true 2>&1 | grep -i "downforce\|options"
```

