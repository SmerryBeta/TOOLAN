package storage

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileItem 是 /api/list 返回给前端和安卓端的统一文件描述。
// Folder/Path 使用 "/" 分隔，Folder 为空表示根目录（未分类）。
type FileItem struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Folder     string    `json:"folder"`
	URL        string    `json:"url"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"createdAt"`
	ModifiedAt time.Time `json:"modifiedAt"`
	Ext        string    `json:"ext"`
	Category   string    `json:"category"`
	MediaType  string    `json:"mediaType"`
}

// FolderInfo 描述当前目录下一级的子文件夹及其中的文件数量。
type FolderInfo struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Count int    `json:"count"`
}

type metadataStore struct {
	path  string
	mu    sync.Mutex
	items map[string]time.Time
}

// FileService 管理 static/images 和 static/files 下的上传、列表和删除。
type FileService struct {
	StaticRoot string
	ImagesDir  string
	FilesDir   string
	meta       *metadataStore
}

// NewFileService 创建文件服务，并确保静态目录和 metadata 文件目录存在。
func NewFileService(staticRoot string) (*FileService, error) {
	service := &FileService{
		StaticRoot: staticRoot,
		ImagesDir:  filepath.Join(staticRoot, "images"),
		FilesDir:   filepath.Join(staticRoot, "files"),
		meta:       newMetadataStore(filepath.Join(staticRoot, "data", "file_meta.json")),
	}
	for _, dir := range []string{service.ImagesDir, service.FilesDir, filepath.Join(staticRoot, "data")} {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return nil, err
		}
	}
	return service, service.meta.load()
}

// ErrFileExists 表示上传目标已有同名文件；handler 据此返回 409 让客户端确认是否覆盖。
var ErrFileExists = errors.New("同名文件已存在")

// ResolveUploadTarget 校验上传文件名与目标文件夹，纯计算保存路径，无任何磁盘副作用
// （不创建目录）。folder 为 "/" 分隔的相对子目录，空表示根目录；relPath 用于 metadata 与 URL。
func (s *FileService) ResolveUploadTarget(fileName string, folder string) (savePath string, kind string, isImage bool, relPath string, err error) {
	if fileName == "" {
		return "", "", false, "", errors.New("未找到上传文件")
	}

	safeName := filepath.Base(filepath.FromSlash(fileName))
	if safeName == "." || safeName == "" || safeName == string(os.PathSeparator) {
		return "", "", false, "", errors.New("文件名无效")
	}
	if isReservedWindowsName(safeName) {
		return "", "", false, "", errors.New("文件名无效")
	}

	cleanFolder, err := cleanRelFolder(folder)
	if err != nil {
		return "", "", false, "", err
	}

	isImage = IsImageExt(filepath.Ext(safeName))
	baseDir := s.FilesDir
	kind = "file"
	if isImage {
		baseDir = s.ImagesDir
		kind = "image"
	}
	targetDir := baseDir
	if cleanFolder != "" {
		targetDir = filepath.Join(baseDir, filepath.FromSlash(cleanFolder))
		// 防御路径穿越：拼接后必须仍在 baseDir 之内。
		if !withinBase(baseDir, targetDir) {
			return "", "", false, "", errors.New("文件夹路径非法")
		}
	}

	relPath = joinSlash(cleanFolder, safeName)
	return filepath.Join(targetDir, safeName), kind, isImage, relPath, nil
}

// EnsureUploadDir 在真正写入前确保 savePath 的父目录存在。
func (s *FileService) EnsureUploadDir(savePath string) error {
	return os.MkdirAll(filepath.Dir(savePath), os.ModePerm)
}

// UploadTargetExists 供上传预检接口使用：计算目标路径并返回是否已存在，无副作用。
func (s *FileService) UploadTargetExists(fileName string, folder string) (exists bool, kind string, relPath string, err error) {
	savePath, k, _, rp, rerr := s.ResolveUploadTarget(fileName, folder)
	if rerr != nil {
		return false, "", "", rerr
	}
	if _, serr := os.Stat(savePath); serr == nil {
		return true, k, rp, nil
	}
	return false, k, rp, nil
}

// RecordUploadMetadata 在 Gin 保存上传文件成功后记录添加时间，relPath 含子目录。
func (s *FileService) RecordUploadMetadata(kind string, relPath string) {
	s.meta.set(metadataKey(kind, relPath), time.Now())
}

// buildItem 根据磁盘文件信息生成 API 返回对象，folder 为 "/" 分隔的相对子目录。
func (s *FileService) buildItem(kind string, name string, folder string, info os.FileInfo) FileItem {
	ext := strings.ToLower(filepath.Ext(name))
	category := CategoryForExt(ext)
	relPath := joinSlash(folder, name)
	createdAt := s.meta.get(metadataKey(kind, relPath), info.ModTime())
	prefix := "/static/files/"
	if kind == "image" {
		prefix = "/static/images/"
	}
	return FileItem{
		Name:       name,
		Path:       relPath,
		Folder:     folder,
		URL:        prefix + relPath,
		Size:       info.Size(),
		CreatedAt:  createdAt,
		ModifiedAt: info.ModTime(),
		Ext:        strings.TrimPrefix(ext, "."),
		Category:   category,
		MediaType:  MediaTypeForCategory(category),
	}
}

// List 返回 folder 指定层级的文件与下一级子文件夹；支持 sort/order/category。folder 为空表示根目录。
// 子文件夹通过先登记当前层级的直接子目录得到，因此空文件夹也会显示（count=0）。
func (s *FileService) List(kind string, sortBy string, order string, category string, folder string) ([]FileItem, []FolderInfo, error) {
	dir, scanKind := s.directoryForKind(kind)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return nil, nil, err
	}
	reqFolder, err := cleanRelFolder(folder)
	if err != nil {
		return nil, nil, err
	}
	currentDir := dir
	if reqFolder != "" {
		currentDir = filepath.Join(dir, filepath.FromSlash(reqFolder))
		if !withinBase(dir, currentDir) {
			return nil, nil, errors.New("文件夹路径非法")
		}
	}

	var files []FileItem
	childFolders := map[string]*FolderInfo{}

	// 先登记直接子目录，保证空文件夹也能显示；后续扫描只负责累加 count。
	if entries, err := os.ReadDir(currentDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				childFolders[e.Name()] = &FolderInfo{Name: e.Name(), Path: joinSlash(reqFolder, e.Name())}
			}
		}
	}

	// 只扫描当前层子树；itemFolder 为相对 currentDir 的路径。
	walkErr := filepath.WalkDir(currentDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(currentDir, path)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		itemFolder := ""
		if idx := strings.LastIndex(relSlash, "/"); idx >= 0 {
			itemFolder = relSlash[:idx]
		}
		// buildItem 需要相对分区根目录的完整 folder 路径来生成 URL/Path/metadata 键。
		item := s.buildItem(scanKind, d.Name(), joinSlash(reqFolder, itemFolder), info)
		if !matchesKind(kind, item.Category) {
			return nil
		}
		if category != "" && category != "all" && item.Category != category {
			return nil
		}

		if itemFolder == "" {
			files = append(files, item)
		} else {
			top := firstSegmentUnder(itemFolder, "")
			agg, ok := childFolders[top]
			if !ok {
				agg = &FolderInfo{Name: top, Path: joinSlash(reqFolder, top)}
				childFolders[top] = agg
			}
			agg.Count++
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, walkErr
	}

	folders := make([]FolderInfo, 0, len(childFolders))
	for _, info := range childFolders {
		folders = append(folders, *info)
	}
	sort.Slice(folders, func(i, j int) bool {
		return strings.ToLower(folders[i].Name) < strings.ToLower(folders[j].Name)
	})

	sortItems(files, sortBy, order)
	return files, folders, nil
}

// Delete 按相对路径批量删除文件，同步清理 metadata，并回收变空的目录。
func (s *FileService) Delete(kind string, paths []string) ([]string, map[string]string) {
	baseDir, metaKind := s.directoryForKind(kind)
	deleted := make([]string, 0, len(paths))
	failed := make(map[string]string)

	for _, relPath := range paths {
		full, err := resolveWithinBase(baseDir, relPath)
		if err != nil {
			failed[relPath] = "非法文件名"
			continue
		}
		if err := os.Remove(full); err != nil {
			failed[relPath] = err.Error()
			continue
		}
		s.meta.delete(metadataKey(metaKind, filepath.ToSlash(relPath)))
		// 不再自动回收空目录：文件夹是一等公民，需通过「删除文件夹」显式删除。
		deleted = append(deleted, filepath.ToSlash(relPath))
	}

	return deleted, failed
}

// CreateFolder 在指定分区创建一个（可多级的）文件夹。
func (s *FileService) CreateFolder(kind string, folder string) error {
	baseDir, _ := s.directoryForKind(kind)
	clean, err := cleanRelFolder(folder)
	if err != nil {
		return err
	}
	if clean == "" {
		return errors.New("文件夹名不能为空")
	}
	target := filepath.Join(baseDir, filepath.FromSlash(clean))
	if !withinBase(baseDir, target) {
		return errors.New("文件夹路径非法")
	}
	return os.MkdirAll(target, os.ModePerm)
}

// DeleteFolder 删除一个空文件夹（含其内已变空的子目录不会被自动处理）。
func (s *FileService) DeleteFolder(kind string, folder string) error {
	baseDir, _ := s.directoryForKind(kind)
	clean, err := cleanRelFolder(folder)
	if err != nil {
		return err
	}
	if clean == "" {
		return errors.New("不能删除根目录")
	}
	target := filepath.Join(baseDir, filepath.FromSlash(clean))
	if !withinBase(baseDir, target) {
		return errors.New("文件夹路径非法")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return errors.New("文件夹非空，无法删除")
	}
	return os.Remove(target)
}

// RenameFolder 重命名/移动一个文件夹（整棵子树），并同步 metadata 键。
func (s *FileService) RenameFolder(kind string, from string, to string) error {
	baseDir, metaKind := s.directoryForKind(kind)
	oldClean, err := cleanRelFolder(from)
	if err != nil {
		return err
	}
	newClean, err := cleanRelFolder(to)
	if err != nil {
		return err
	}
	if oldClean == "" || newClean == "" {
		return errors.New("文件夹名不能为空")
	}
	if oldClean == newClean {
		return nil
	}
	oldPath := filepath.Join(baseDir, filepath.FromSlash(oldClean))
	newPath := filepath.Join(baseDir, filepath.FromSlash(newClean))
	if !withinBase(baseDir, oldPath) || !withinBase(baseDir, newPath) {
		return errors.New("文件夹路径非法")
	}
	if _, err := os.Stat(oldPath); err != nil {
		return errors.New("原文件夹不存在")
	}
	if _, err := os.Stat(newPath); err == nil {
		return errors.New("目标文件夹已存在")
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	s.meta.renamePrefix(metadataKey(metaKind, oldClean)+"/", metadataKey(metaKind, newClean)+"/")
	return nil
}

// MoveItems 将一批文件移动到目标文件夹，返回成功与失败的相对路径。
func (s *FileService) MoveItems(kind string, paths []string, toFolder string) ([]string, map[string]string) {
	baseDir, metaKind := s.directoryForKind(kind)
	clean, err := cleanRelFolder(toFolder)
	moved := make([]string, 0, len(paths))
	failed := make(map[string]string)
	if err != nil {
		for _, p := range paths {
			failed[p] = err.Error()
		}
		return moved, failed
	}

	targetDir := baseDir
	if clean != "" {
		targetDir = filepath.Join(baseDir, filepath.FromSlash(clean))
		if !withinBase(baseDir, targetDir) {
			for _, p := range paths {
				failed[p] = "目标文件夹非法"
			}
			return moved, failed
		}
		if err := os.MkdirAll(targetDir, os.ModePerm); err != nil {
			for _, p := range paths {
				failed[p] = err.Error()
			}
			return moved, failed
		}
	}

	for _, relPath := range paths {
		srcFull, err := resolveWithinBase(baseDir, relPath)
		if err != nil {
			failed[relPath] = "非法文件名"
			continue
		}
		oldFolder := ""
		if idx := strings.LastIndex(filepath.ToSlash(relPath), "/"); idx >= 0 {
			oldFolder = filepath.ToSlash(relPath)[:idx]
		}
		if oldFolder == clean {
			moved = append(moved, filepath.ToSlash(relPath)) // 已在目标文件夹，视为成功
			continue
		}
		name := filepath.Base(srcFull)
		dstFull := filepath.Join(targetDir, name)
		if _, err := os.Stat(dstFull); err == nil {
			failed[relPath] = "目标已存在同名文件"
			continue
		}
		if err := os.Rename(srcFull, dstFull); err != nil {
			failed[relPath] = err.Error()
			continue
		}
		newRel := joinSlash(clean, name)
		if createdAt, ok := s.meta.take(metadataKey(metaKind, filepath.ToSlash(relPath))); ok {
			s.meta.set(metadataKey(metaKind, newRel), createdAt)
		}
		// 不再自动回收源空目录：文件夹是一等公民，移空后保留以便显式删除。
		moved = append(moved, newRel)
	}

	return moved, failed
}

// RenameItem 修改单个文件的名称：保留所在文件夹与原扩展名（newName 为不含扩展名的主名）。
// 锁死扩展名可避免 category 变化导致文件从当前分区列表中"消失"。返回重命名后的相对路径。
func (s *FileService) RenameItem(kind string, path string, newName string) (string, error) {
	baseDir, metaKind := s.directoryForKind(kind)
	srcFull, err := resolveWithinBase(baseDir, path)
	if err != nil {
		return "", errors.New("非法路径")
	}
	info, err := os.Stat(srcFull)
	if err != nil {
		return "", errors.New("文件不存在")
	}
	if info.IsDir() {
		return "", errors.New("目标是文件夹，请使用文件夹重命名")
	}

	stem := strings.TrimSpace(newName)
	if stem == "" {
		return "", errors.New("名称不能为空")
	}
	if strings.ContainsAny(stem, "/\\") || strings.Contains(stem, "..") || strings.ContainsRune(stem, rune(0)) {
		return "", errors.New("名称非法")
	}

	oldName := filepath.Base(srcFull)
	oldExt := filepath.Ext(oldName)
	newBase := stem + oldExt

	relSlash := filepath.ToSlash(path)
	folder := ""
	if idx := strings.LastIndex(relSlash, "/"); idx >= 0 {
		folder = relSlash[:idx]
	}
	newRel := joinSlash(folder, newBase)

	if newBase == oldName {
		return newRel, nil // 名称未变化，直接成功
	}
	dstFull := filepath.Join(filepath.Dir(srcFull), newBase)
	if !withinBase(baseDir, dstFull) {
		return "", errors.New("非法路径")
	}
	if _, err := os.Stat(dstFull); err == nil {
		return "", errors.New("同名文件已存在")
	}
	if err := os.Rename(srcFull, dstFull); err != nil {
		return "", err
	}
	if createdAt, ok := s.meta.take(metadataKey(metaKind, relSlash)); ok {
		s.meta.set(metadataKey(metaKind, newRel), createdAt)
	}
	return newRel, nil
}

// OpenFile 打开分区内相对路径的文件供加密下载端点流式读取；
// 拒绝目录与越界路径，调用方负责 Close。
func (s *FileService) OpenFile(kind string, relPath string) (*os.File, os.FileInfo, error) {
	baseDir, _ := s.directoryForKind(kind)
	full, err := resolveWithinBase(baseDir, relPath)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if info.IsDir() {
		_ = f.Close()
		return nil, nil, errors.New("不能下载文件夹")
	}
	return f, info, nil
}

// WriteZip streams the requested files into w as a zip archive, skipping unsafe or missing paths.
// It returns how many files were added so callers can decide whether the result is worth sending.
// Folder structure is preserved inside the archive via each file's relative path.
func (s *FileService) WriteZip(kind string, paths []string, w io.Writer) (int, error) {
	baseDir, _ := s.directoryForKind(kind)
	zw := zip.NewWriter(w)

	added := 0
	for _, relPath := range paths {
		full, err := resolveWithinBase(baseDir, relPath)
		if err != nil {
			continue
		}
		info, err := os.Stat(full)
		if err != nil || info.IsDir() {
			continue
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			continue
		}
		header.Name = filepath.ToSlash(relPath)
		header.Method = zip.Deflate

		entry, err := zw.CreateHeader(header)
		if err != nil {
			continue
		}
		file, err := os.Open(full)
		if err != nil {
			continue
		}
		_, err = io.Copy(entry, file)
		_ = file.Close()
		if err != nil {
			return added, err
		}
		added++
	}

	return added, zw.Close()
}

// ZipEntryInfo 描述 zip 归档内的一个文件条目。
type ZipEntryInfo struct {
	Name string `json:"name"` // 压缩包内的相对路径（"/" 分隔）
	Size int64  `json:"size"` // 解压后的字节数
}

// ZipEntries 打开给定 zip（相对分区路径），列出其中所有文件条目（跳过目录）。
func (s *FileService) ZipEntries(kind string, zipPath string) ([]ZipEntryInfo, error) {
	baseDir, _ := s.directoryForKind(kind)
	full, err := resolveWithinBase(baseDir, zipPath)
	if err != nil {
		return nil, errors.New("非法路径")
	}
	r, err := zip.OpenReader(full)
	if err != nil {
		return nil, errors.New("无法读取压缩包")
	}
	defer r.Close()

	entries := make([]ZipEntryInfo, 0, len(r.File))
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, "/") { // 目录条目
			continue
		}
		name := strings.TrimPrefix(f.Name, "./")
		if name == "" {
			continue
		}
		entries = append(entries, ZipEntryInfo{Name: name, Size: int64(f.UncompressedSize64)})
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries, nil
}

// OpenZipEntry 从 zip 中定位并打开指定条目。返回的 *zip.ReadCloser 与 io.ReadCloser
// 均需由调用方 Close（先关 rc，再关 rc 对应的 ReadCloser）。entry 按压缩包内相对路径精确匹配。
func (s *FileService) OpenZipEntry(kind string, zipPath string, entry string) (*zip.ReadCloser, io.ReadCloser, ZipEntryInfo, error) {
	baseDir, _ := s.directoryForKind(kind)
	full, err := resolveWithinBase(baseDir, zipPath)
	if err != nil {
		return nil, nil, ZipEntryInfo{}, errors.New("非法路径")
	}
	r, err := zip.OpenReader(full)
	if err != nil {
		return nil, nil, ZipEntryInfo{}, errors.New("无法读取压缩包")
	}
	want := strings.TrimPrefix(filepath.ToSlash(entry), "./")
	if want == "" || strings.Contains(want, "..") {
		r.Close()
		return nil, nil, ZipEntryInfo{}, errors.New("条目名非法")
	}
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		if strings.TrimPrefix(f.Name, "./") != want {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			r.Close()
			return nil, nil, ZipEntryInfo{}, errors.New("无法读取文件")
		}
		return r, rc, ZipEntryInfo{Name: want, Size: int64(f.UncompressedSize64)}, nil
	}
	r.Close()
	return nil, nil, ZipEntryInfo{}, errors.New("压缩包内未找到该文件")
}

func (s *FileService) directoryForKind(kind string) (string, string) {
	if kind == "image" {
		return s.ImagesDir, "image"
	}
	return s.FilesDir, "file"
}

func newMetadataStore(path string) *metadataStore {
	return &metadataStore{path: path, items: map[string]time.Time{}}
}

func (m *metadataStore) load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &m.items)
}

func (m *metadataStore) get(key string, fallback time.Time) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	if value, ok := m.items[key]; ok {
		return value
	}
	return fallback
}

func (m *metadataStore) set(key string, value time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = value
	_ = m.saveLocked()
}

func (m *metadataStore) delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	_ = m.saveLocked()
}

// take 返回并删除一个键，用于移动文件时搬运 createdAt。
func (m *metadataStore) take(key string) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.items[key]
	if ok {
		delete(m.items, key)
		_ = m.saveLocked()
	}
	return value, ok
}

// renamePrefix 批量把以 oldPrefix 开头的键改写为 newPrefix，用于文件夹重命名。
func (m *metadataStore) renamePrefix(oldPrefix string, newPrefix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := false
	for key, value := range m.items {
		if strings.HasPrefix(key, oldPrefix) {
			items := newPrefix + strings.TrimPrefix(key, oldPrefix)
			m.items[items] = value
			delete(m.items, key)
			changed = true
		}
	}
	if changed {
		_ = m.saveLocked()
	}
}

func (m *metadataStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.path), os.ModePerm); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0644)
}

func metadataKey(kind string, name string) string {
	return kind + "/" + name
}

func isSafeName(name string) bool {
	return name != "" && filepath.Base(name) == name && !strings.Contains(name, "..")
}

// cleanRelFolder 规范化相对文件夹路径：统一 "/" 分隔、去掉空段与 "."，拒绝 ".." 越界。
// 返回 "" 表示根目录。
func cleanRelFolder(folder string) (string, error) {
	folder = strings.TrimSpace(filepath.ToSlash(folder))
	if folder == "" || folder == "/" {
		return "", nil
	}
	var segments []string
	for _, seg := range strings.Split(folder, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			return "", errors.New("文件夹路径非法")
		}
		if strings.ContainsRune(seg, rune(0)) {
			return "", errors.New("文件夹名非法")
		}
		if isReservedWindowsName(seg) {
			return "", errors.New("文件夹名非法")
		}
		segments = append(segments, seg)
	}
	return strings.Join(segments, "/"), nil
}

// isReservedWindowsName 拒绝 Windows 保留设备名（含带扩展名形式），
// 避免写入 CON/NUL 等被系统重定向到设备导致写入异常或挂起。
func isReservedWindowsName(name string) bool {
	stem := strings.ToLower(name)
	if idx := strings.IndexByte(stem, '.'); idx >= 0 {
		stem = stem[:idx]
	}
	switch stem {
	case "con", "prn", "aux", "nul",
		"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
		"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9":
		return true
	}
	return false
}

// joinSlash 拼接文件夹与文件名/子文件夹为相对路径（"/" 分隔）。
func joinSlash(folder string, name string) string {
	if folder == "" {
		return name
	}
	if name == "" {
		return folder
	}
	return folder + "/" + name
}

// isUnder 判断 child 是否为 parent 目录层级下的子路径（parent 为空代表根）。
func isUnder(parent string, child string) bool {
	if child == "" || child == parent {
		return false
	}
	if parent == "" {
		return true
	}
	return strings.HasPrefix(child, parent+"/")
}

// firstSegmentUnder 取 child 相对 parent 的第一段目录名。
func firstSegmentUnder(child string, parent string) string {
	rest := child
	if parent != "" {
		rest = strings.TrimPrefix(child, parent+"/")
	}
	if idx := strings.Index(rest, "/"); idx >= 0 {
		return rest[:idx]
	}
	return rest
}

// withinBase 判断 target 规范化后是否仍位于 base 之内（防路径穿越）。
func withinBase(base string, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != string(os.PathSeparator)
}

// resolveWithinBase 将相对路径安全地拼到 baseDir 下，拒绝越界与非法名。
func resolveWithinBase(baseDir string, relPath string) (string, error) {
	rel := filepath.ToSlash(strings.TrimSpace(relPath))
	if rel == "" {
		return "", errors.New("空路径")
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			if seg == ".." {
				return "", errors.New("非法路径")
			}
			continue
		}
	}
	full := filepath.Join(baseDir, filepath.FromSlash(rel))
	if !withinBase(baseDir, full) || full == baseDir {
		return "", errors.New("非法路径")
	}
	return full, nil
}

// pruneEmptyDirs 自底向上删除变空的目录，遇到 baseDir 或非空目录即停止。
// 目前无调用点（删除/移动不再自动回收空目录），保留以备显式清理使用。
func pruneEmptyDirs(dir string, baseDir string) {
	for dir != baseDir && withinBase(baseDir, dir) && strings.HasPrefix(dir, baseDir) {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			return
		}
		if err := os.Remove(dir); err != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}

func matchesKind(kind string, category string) bool {
	switch kind {
	case "image":
		return category == "image"
	case "video":
		return category == "video"
	case "audio":
		return category == "audio"
	case "file":
		return category != "image" && category != "video"
	default:
		return true
	}
}

func sortItems(items []FileItem, sortBy string, order string) {
	desc := order != "asc"
	sort.SliceStable(items, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "name":
			less = strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
		case "size":
			less = items[i].Size < items[j].Size
		case "type", "category":
			less = items[i].Category < items[j].Category
		default:
			less = items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		if desc {
			return !less
		}
		return less
	})
}

func IsImageExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".avif":
		return true
	default:
		return false
	}
}

func IsVideoExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".mp4", ".webm", ".ogv", ".mov", ".m4v", ".mkv":
		return true
	default:
		return false
	}
}

func IsAudioExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".oga", ".opus", ".weba", ".aiff", ".aif", ".alac":
		return true
	default:
		return false
	}
}

func CategoryForExt(ext string) string {
	ext = strings.ToLower(ext)
	if IsImageExt(ext) {
		return "image"
	}
	if IsVideoExt(ext) {
		return "video"
	}
	if IsAudioExt(ext) {
		return "audio"
	}
	switch ext {
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".csv",
		".json", ".xml", ".html", ".css", ".js", ".ts", ".py", ".rb", ".go", ".java",
		".c", ".cpp", ".h", ".hpp", ".rs", ".php", ".swift", ".kotlin", ".dart",
		".jsx", ".tsx", ".vue", ".mdx", ".ipynb", ".sql", ".bash",
		".sh", ".zsh", ".fish", ".bat", ".cmd", ".ps1", ".vbs", ".jsh",
		".yml", ".yaml", ".toml", ".ini", ".env", ".cfg", ".conf",
		".htaccess", ".htpasswd", ".log":
		return "document"
	case ".zip", ".rar", ".7z", ".tar", ".gz":
		return "archive"
	default:
		return "other"
	}
}

func MediaTypeForCategory(category string) string {
	switch category {
	case "image":
		return "image"
	case "video":
		return "video"
	case "audio":
		return "audio"
	default:
		return "file"
	}
}

func DetectContentType(name string) string {
	switch CategoryForExt(filepath.Ext(name)) {
	case "image":
		return "image/*"
	case "video":
		return "video/*"
	case "audio":
		return "audio/*"
	default:
		return http.DetectContentType([]byte(name))
	}
}
