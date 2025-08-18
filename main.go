package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 扫描任务结构
type ScanTask struct {
	IP   string
	Port int
}

// 扫描结果结构
type ScanResult struct {
	IP   string
	Port int
}

// 将CIDR格式的IP段转换为IP列表（支持IPv4和IPv6）
func expandCIDR(cidr string) ([]string, error) {
	// 检查是否为单个IP
	if !strings.Contains(cidr, "/") {
		if net.ParseIP(cidr) != nil {
			return []string{cidr}, nil
		}
		return nil, fmt.Errorf("无效的IP地址: %s", cidr)
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	
	// IPv6处理
	if ipnet.IP.To4() == nil {
		// IPv6网段，由于地址空间巨大，限制扫描范围
		ip := ipnet.IP.Mask(ipnet.Mask)
		maxIPs := 1000 // 限制IPv6扫描数量避免内存溢出
		count := 0
		
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip) && count < maxIPs; incIPv6(ip) {
			ips = append(ips, ip.String())
			count++
		}
		
		if count >= maxIPs {
			fmt.Printf("警告: IPv6网段 %s 包含大量地址，仅扫描前%d个\n", cidr, maxIPs)
		}
	} else {
		// IPv4处理
		ip := ipnet.IP.Mask(ipnet.Mask)
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIPv4(ip) {
			ips = append(ips, ip.String())
		}
	}
	
	return ips, nil
}

// IPv4地址递增
func incIPv4(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IPv6地址递增
func incIPv6(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 检测IP版本并格式化地址
func formatAddress(ip string, port int) string {
	if strings.Contains(ip, ":") {
		// IPv6地址需要用方括号包围
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	// IPv4地址
	return fmt.Sprintf("%s:%d", ip, port)
}

// 扫描单个IP的指定端口
func scanPort(ip string, port int, timeout time.Duration) bool {
	target := formatAddress(ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// 实时写入文件的goroutine
func fileWriter(results <-chan ScanResult, outputFile string, wg *sync.WaitGroup, foundCount *int64) {
	defer wg.Done()
	
	// 创建或打开输出文件
	file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("无法创建输出文件 %s: %v\n", outputFile, err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 实时写入发现的开放端口
	for result := range results {
		fmt.Printf("发现开放端口: %s\n", formatAddress(result.IP, result.Port))
		fmt.Fprintf(writer, "%s\n", formatAddress(result.IP, result.Port))
		writer.Flush() // 立即刷新到文件
		atomic.AddInt64(foundCount, 1)
	}
}

// 工作者goroutine
func worker(jobs <-chan ScanTask, results chan<- ScanResult, timeout time.Duration, wg *sync.WaitGroup, scannedCount *int64) {
	defer wg.Done()
	for task := range jobs {
		if scanPort(task.IP, task.Port, timeout) {
			results <- ScanResult{IP: task.IP, Port: task.Port}
		}
		atomic.AddInt64(scannedCount, 1)
	}
}

// 计算推荐并发数
func calculateWorkerCount() int {
	cpuCount := runtime.NumCPU()
	// 激进策略
	workerCount := cpuCount * 250
	
	// 设置合理的范围
	if workerCount < 100 {
		workerCount = 100
	} else if workerCount > 5000 {
		workerCount = 5000
	}
	
	return workerCount
}

// 估算扫描时间和流量
func estimateResources(totalTasks int, workerCount int, timeout time.Duration) (time.Duration, float64) {
	// 估算时间：考虑并发效率和网络延迟
	avgTimePerTask := timeout / 3 // 假设平均1/3的超时时间完成扫描
	estimatedTime := time.Duration(totalTasks) * avgTimePerTask / time.Duration(workerCount)
	
	// 估算流量：每个TCP连接约1-2KB数据交换
	estimatedTrafficMB := float64(totalTasks) * 1.5 / 1024 // 转换为MB
	
	return estimatedTime, estimatedTrafficMB
}

// 进度显示goroutine
func progressMonitor(totalTasks int, scannedCount *int64, foundCount *int64, startTime time.Time) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		scanned := atomic.LoadInt64(scannedCount)
		found := atomic.LoadInt64(foundCount)
		
		if scanned >= int64(totalTasks) {
			break
		}
		
		progress := float64(scanned) / float64(totalTasks) * 100
		elapsed := time.Since(startTime)
		
		if scanned > 0 {
			eta := time.Duration(float64(elapsed) * float64(totalTasks) / float64(scanned))
			remaining := eta - elapsed
			fmt.Printf("进度: %.1f%% (%d/%d) | 已发现: %d | 已用时: %v | 预计剩余: %v\n", 
				progress, scanned, totalTasks, found, elapsed.Round(time.Second), remaining.Round(time.Second))
		}
	}
}

// 解析端口参数
func parsePorts(portStr string) ([]int, error) {
	if portStr == "" {
		return []int{80}, nil // 默认端口
	}
	
	portParts := strings.Split(portStr, ",")
	var ports []int
	
	for _, part := range portParts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		// 检查是否为端口范围（如：8000-9000）
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("无效的端口范围格式: %s，正确格式如: 8000-9000", part)
			}
			
			startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("无效的起始端口号: %s", rangeParts[0])
			}
			
			endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("无效的结束端口号: %s", rangeParts[1])
			}
			
			if startPort < 1 || startPort > 65535 {
				return nil, fmt.Errorf("起始端口号超出范围(1-65535): %d", startPort)
			}
			
			if endPort < 1 || endPort > 65535 {
				return nil, fmt.Errorf("结束端口号超出范围(1-65535): %d", endPort)
			}
			
			if startPort > endPort {
				return nil, fmt.Errorf("起始端口号不能大于结束端口号: %d > %d", startPort, endPort)
			}
			
			// 添加范围内的所有端口
			for port := startPort; port <= endPort; port++ {
				ports = append(ports, port)
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("无效的端口号: %s", part)
			}
			
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("端口号超出范围(1-65535): %d", port)
			}
			
			ports = append(ports, port)
		}
	}
	
	if len(ports) == 0 {
		return []int{80}, nil // 默认端口
	}
	
	return ports, nil
}

func main() {
	// 命令行参数解析
	var portStr string
	var concurrency int
	var timeoutSeconds int
	flag.StringVar(&portStr, "p", "80", "要扫描的端口，支持单个端口、多个端口和端口范围，例如: -p 22,80,443,10808 或 -p 80-90,443,8000-8010")

	flag.IntVar(&concurrency, "c", 0, "自定义并发数，0表示使用自动计算值，建议范围: 1000-5000")
	flag.IntVar(&timeoutSeconds, "t", 1, "连接超时时间(秒)，默认1秒")
	flag.Parse()

	// 设置超时时间
	timeout := time.Duration(timeoutSeconds) * time.Second

	const (
		inputFile = "ip.txt"         // 输入文件
		outputFile = "open.txt"       // 输出文件
	)

	fmt.Println("=== 高并发多端口扫描器 ===")
	
	// 解析端口
	ports, err := parsePorts(portStr)
	if err != nil {
		fmt.Printf("端口解析错误: %v\n", err)
		return
	}
	
	// 获取系统信息
	cpuCount := runtime.NumCPU()
	workerCount := calculateWorkerCount()
	
	// 如果用户指定了并发数，则使用用户指定的值
	if concurrency > 0 {
		if concurrency < 10 {
			fmt.Printf("警告: 并发数过低(%d)，建议至少100\n", concurrency)
		} else if concurrency > 10000 {
			fmt.Printf("警告: 并发数过高(%d)，可能导致系统资源耗尽\n", concurrency)
		}
		workerCount = concurrency
		fmt.Printf("系统信息: CPU核心数=%d, 用户指定并发数=%d\n", cpuCount, workerCount)
	} else {
		fmt.Printf("系统信息: CPU核心数=%d, 自动计算并发数=%d (激进策略)\n", cpuCount, workerCount)
	}
	fmt.Printf("扫描端口: %v\n", ports)

	// 读取IP段文件
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("无法打开文件 %s: %v\n", inputFile, err)
		return
	}
	defer file.Close()

	// 解析所有IP段和单个IP，生成IP列表
	var allIPs []string
	scanner := bufio.NewScanner(file)
	fmt.Println("正在解析IP地址...")
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		ips, err := expandCIDR(line)
		if err != nil {
			fmt.Printf("解析失败 %s: %v\n", line, err)
			continue
		}
		allIPs = append(allIPs, ips...)
		
		if strings.Contains(line, "/") {
			fmt.Printf("已解析IP段 %s: %d个IP\n", line, len(ips))
		} else {
			fmt.Printf("已添加IP %s\n", line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("读取文件错误: %v\n", err)
		return
	}

	totalIPs := len(allIPs)
	totalTasks := totalIPs * len(ports)
	
	if totalIPs == 0 {
		fmt.Println("没有找到有效的IP地址")
		return
	}

	// 估算资源消耗
	estimatedTime, estimatedTrafficMB := estimateResources(totalTasks, workerCount, timeout)
	
	fmt.Printf("\n=== 扫描预估 ===\n")
	fmt.Printf("IP数量: %d\n", totalIPs)
	fmt.Printf("端口数量: %d\n", len(ports))
	fmt.Printf("总任务数: %d\n", totalTasks)
	fmt.Printf("并发数量: %d\n", workerCount)
	fmt.Printf("预计用时: %v\n", estimatedTime.Round(time.Second))
	fmt.Printf("预计流量: %.2f MB\n", estimatedTrafficMB)
	fmt.Printf("结果文件: %s\n", outputFile)
	fmt.Println("=================\n")

	// 清空输出文件
	if err := os.WriteFile(outputFile, []byte{}, 0644); err != nil {
		fmt.Printf("无法创建输出文件: %v\n", err)
		return
	}

	// 创建任务队列和结果队列
	jobs := make(chan ScanTask, workerCount*2)
	results := make(chan ScanResult, workerCount)

	// 计数器
	var scannedCount int64
	var foundCount int64

	// 启动文件写入goroutine
	var fileWg sync.WaitGroup
	fileWg.Add(1)
	go fileWriter(results, outputFile, &fileWg, &foundCount)

	// 启动工作者goroutine池
	var workerWg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workerWg.Add(1)
		go worker(jobs, results, timeout, &workerWg, &scannedCount)
	}

	// 记录开始时间
	startTime := time.Now()
	
	// 启动进度监控
	go progressMonitor(totalTasks, &scannedCount, &foundCount, startTime)

	// 发送扫描任务
	go func() {
		for _, ip := range allIPs {
			for _, port := range ports {
				jobs <- ScanTask{IP: ip, Port: port}
			}
		}
		close(jobs)
	}()

	// 等待所有工作者完成
	go func() {
		workerWg.Wait()
		close(results)
	}()

	// 等待文件写入完成
	fileWg.Wait()

	// 输出最终统计结果
	actualTime := time.Since(startTime)
	finalFound := atomic.LoadInt64(&foundCount)
	
	fmt.Printf("\n=== 扫描完成 ===\n")
	fmt.Printf("总计扫描: %d 个任务 (%d IP × %d 端口)\n", totalTasks, totalIPs, len(ports))
	fmt.Printf("端口开放: %d 个\n", finalFound)
	fmt.Printf("实际用时: %v\n", actualTime.Round(time.Second))
	fmt.Printf("扫描速度: %.0f 任务/秒\n", float64(totalTasks)/actualTime.Seconds())
	fmt.Printf("端口开放率: %.2f%%\n", float64(finalFound)/float64(totalTasks)*100)
	fmt.Printf("结果已保存到: %s\n", outputFile)
}
