package _139

import (
	"context"
	"crypto/sha256" // 【优化引入】用于纯内存计算哈希
	"encoding/hex"  // 【优化引入】用于哈希字节转十六进制字符串
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings" // 【优化引入】用于强转大写哈希
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	streamPkg "github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/cron"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils/random"
	log "github.com/sirupsen/logrus"
)

type Yun139 struct {
	model.Storage
	Addition
	cron              *cron.Cron
	Account           string
	ref               *Yun139
	PersonalCloudHost string
	RootPath          string
}

func (d *Yun139) Config() driver.Config {
	return config
}

func (d *Yun139) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *Yun139) Init(ctx context.Context) error {
	if d.ref == nil {
		if len(d.Authorization) == 0 {
			if d.Username != "" && d.Password != "" {
				log.Infof("139yun: authorization is empty, trying to login with password.")
				newAuth, err := d.loginWithPassword()
				log.Debugf("newAuth: Ok: %s", newAuth)
				if err != nil {
					return fmt.Errorf("login with password failed: %w", err)
				}
			} else {
				return fmt.Errorf("authorization is empty and username/password is not provided")
			}
		}
		err := d.refreshToken()
		if err != nil {
			return err
		}

		// Query Route Policy
		var resp QueryRoutePolicyResp
		_, err = d.requestRoute(base.Json{
			"userInfo": base.Json{
				"userType":    1,
				"accountType": 1,
				"accountName": d.Account,
			},
			"modAddrType": 1,
		}, &resp)
		if err != nil {
			return err
		}
		for _, policyItem := range resp.Data.RoutePolicyList {
			if policyItem.ModName == "personal" {
				d.PersonalCloudHost = policyItem.HttpsUrl
				break
			}
		}
		if len(d.PersonalCloudHost) == 0 {
			return fmt.Errorf("PersonalCloudHost is empty")
		}

		d.cron = cron.NewCron(time.Hour * 12)
		d.cron.Do(func() {
			err := d.refreshToken()
			if err != nil {
				log.Errorf("%+v", err)
			}
		})
	}
	switch d.Addition.Type {
	case MetaPersonalNew:
		if len(d.Addition.RootFolderID) == 0 {
			d.RootFolderID = "/"
		}
	case MetaPersonal:
		if len(d.Addition.RootFolderID) == 0 {
			d.RootFolderID = "root"
		}
	case MetaGroup:
		if len(d.Addition.RootFolderID) == 0 {
			d.RootFolderID = d.CloudID
		}
		_, err := d.groupGetFiles(d.RootFolderID)
		if err != nil {
			return err
		}
	case MetaFamily:
		if len(d.Addition.RootFolderID) == 0 {
			// Attempt to obtain data.path as the root via a query and persist it.
			if root, err := d.getFamilyRootPath(d.CloudID); err == nil && root != "" {
				d.RootFolderID = root
				op.MustSaveDriverStorage(d)
			}
		}
		_, err := d.familyGetFiles(d.RootFolderID)
		if err != nil {
			return err
		}
	default:
		return errs.NotImplement
	}
	return nil
}

func (d *Yun139) InitReference(storage driver.Driver) error {
	refStorage, ok := storage.(*Yun139)
	if ok {
		d.ref = refStorage
		return nil
	}
	return errs.NotSupport
}

func (d *Yun139) Drop(ctx context.Context) error {
	if d.cron != nil {
		d.cron.Stop()
	}
	d.ref = nil
	return nil
}

func (d *Yun139) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	switch d.Addition.Type {
	case MetaPersonalNew:
		return d.personalGetFiles(dir.GetID())
	case MetaPersonal:
		return d.getFiles(dir.GetID())
	case MetaFamily:
		return d.familyGetFiles(dir.GetID())
	case MetaGroup:
		return d.groupGetFiles(dir.GetID())
	default:
		return nil, errs.NotImplement
	}
}

func (d *Yun139) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	var url string
	var err error
	switch d.Addition.Type {
	case MetaPersonalNew:
		url, err = d.personalGetLink(file.GetID())
	case MetaPersonal:
		url, err = d.getLink(file.GetID())
	case MetaFamily:
		url, err = d.familyGetLink(file.GetID(), file.GetPath())
	case MetaGroup:
		url, err = d.groupGetLink(file.GetID(), file.GetPath())
	default:
		return nil, errs.NotImplement
	}
	if err != nil {
		return nil, err
	}
	return &model.Link{URL: url}, nil
}

func (d *Yun139) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	var err error
	switch d.Addition.Type {
	case MetaPersonalNew:
		data := base.Json{
			"parentFileId":   parentDir.GetID(),
			"name":           dirName,
			"description":    "",
			"type":           "folder",
			"fileRenameMode": "force_rename",
		}
		pathname := "/file/create"
		_, err = d.personalPost(pathname, data, nil)
	case MetaPersonal:
		data := base.Json{
			"createCatalogExtReq": base.Json{
				"parentCatalogID": parentDir.GetID(),
				"newCatalogName":  dirName,
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
			},
		}
		pathname := "/orchestration/personalCloud/catalog/v1.0/createCatalogExt"
		_, err = d.post(pathname, data, nil)
	case MetaFamily:
		data := base.Json{
			"cloudID": d.CloudID,
			"commonAccountInfo": base.Json{
				"account":     d.getAccount(),
				"accountType": 1,
			},
			"docLibName": dirName,
			"path":       path.Join(parentDir.GetPath(), parentDir.GetID()),
		}
		pathname := "/orchestration/familyCloud-rebuild/cloudCatalog/v1.0/createCloudDoc"
		_, err = d.post(pathname, data, nil)
	case MetaGroup:
		data := base.Json{
			"catalogName": dirName,
			"commonAccountInfo": base.Json{
				"account":     d.getAccount(),
				"accountType": 1,
			},
			"groupID":      d.CloudID,
			"parentFileId": parentDir.GetID(),
			"path":         path.Join(parentDir.GetPath(), parentDir.GetID()),
		}
		pathname := "/orchestration/group-rebuild/catalog/v1.0/createGroupCatalog"
		_, err = d.post(pathname, data, nil)
	default:
		err = errs.NotImplement
	}
	return err
}

func (d *Yun139) Move(ctx context.Context, srcObj, dstDir model.Obj) (model.Obj, error) {
	switch d.Addition.Type {
	case MetaPersonalNew:
		data := base.Json{
			"fileIds":        []string{srcObj.GetID()},
			"toParentFileId": dstDir.GetID(),
		}
		pathname := "/file/batchMove"
		_, err := d.personalPost(pathname, data, nil)
		if err != nil {
			return nil, err
		}
		return srcObj, nil
	case MetaGroup:
		var contentList []string
		var catalogList []string
		if srcObj.IsDir() {
			catalogList = append(catalogList, srcObj.GetID())
		} else {
			contentList = append(contentList, srcObj.GetID())
		}
		data := base.Json{
			"taskType":    3,
			"srcType":     2,
			"srcGroupID":  d.CloudID,
			"destType":    2,
			"destGroupID": d.CloudID,
			"destPath":    dstDir.GetPath(),
			"contentList": contentList,
			"catalogList": catalogList,
			"commonAccountInfo": base.Json{
				"account":     d.getAccount(),
				"accountType": 1,
			},
		}
		pathname := "/orchestration/group-rebuild/task/v1.0/createBatchOprTask"
		_, err := d.post(pathname, data, nil)
		if err != nil {
			return nil, err
		}
		return srcObj, nil
	case MetaPersonal:
		var contentInfoList []string
		var catalogInfoList []string
		if srcObj.IsDir() {
			catalogInfoList = append(catalogInfoList, srcObj.GetID())
		} else {
			contentInfoList = append(contentInfoList, srcObj.GetID())
		}
		data := base.Json{
			"createBatchOprTaskReq": base.Json{
				"taskType":   3,
				"actionType": "304",
				"taskInfo": base.Json{
					"contentInfoList": contentInfoList,
					"catalogInfoList": catalogInfoList,
					"newCatalogID":    dstDir.GetID(),
				},
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
			},
		}
		pathname := "/orchestration/personalCloud/batchOprTask/v1.0/createBatchOprTask"
		_, err := d.post(pathname, data, nil)
		if err != nil {
			return nil, err
		}
		return srcObj, nil
	case MetaFamily:
		pathname := "/isbo/openApi/createBatchOprTask"
		var contentList []string
		var catalogList []string
		if srcObj.IsDir() {
			catalogList = append(catalogList, path.Join(srcObj.GetPath(), srcObj.GetID()))
		} else {
			contentList = append(contentList, path.Join(srcObj.GetPath(), srcObj.GetID()))
		}

		body := base.Json{
			"catalogList": catalogList,
			"accountInfo": base.Json{
				"accountName": d.getAccount(),
				"accountType": "1",
			},
			"contentList":   contentList,
			"destCatalogID": dstDir.GetID(),
			"destGroupID":   d.CloudID,
			"destPath":      path.Join(dstDir.GetPath(), dstDir.GetID()),
			"destType":      0,
			"srcGroupID":    d.CloudID,
			"srcType":       0,
			"taskType":      3,
		}

		var resp CreateBatchOprTaskResp
		_, err := d.isboPost(pathname, body, &resp)
		if err != nil {
			return nil, err
		}
		log.Debugf("[139] Move MetaFamily CreateBatchOprTaskResp.Result.ResultCode: %s", resp.Result.ResultCode)
		if resp.Result.ResultCode != "0" {
			return nil, fmt.Errorf("failed to move in family cloud: %s", resp.Result.ResultDesc)
		}
		return srcObj, nil
	default:
		return nil, errs.NotImplement
	}
}

func (d *Yun139) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	var err error
	switch d.Addition.Type {
	case MetaPersonalNew:
		data := base.Json{
			"fileId":      srcObj.GetID(),
			"name":        newName,
			"description": "",
		}
		pathname := "/file/update"
		_, err = d.personalPost(pathname, data, nil)
	case MetaPersonal:
		var data base.Json
		var pathname string
		if srcObj.IsDir() {
			data = base.Json{
				"catalogID":   srcObj.GetID(),
				"catalogName": newName,
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
			}
			pathname = "/orchestration/personalCloud/catalog/v1.0/updateCatalogInfo"
		} else {
			data = base.Json{
				"contentID":   srcObj.GetID(),
				"contentName": newName,
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
			}
			pathname = "/orchestration/personalCloud/content/v1.0/updateContentInfo"
		}
		_, err = d.post(pathname, data, nil)
	case MetaGroup:
		var data base.Json
		var pathname string
		if srcObj.IsDir() {
			data = base.Json{
				"groupID":           d.CloudID,
				"modifyCatalogID":   srcObj.GetID(),
				"modifyCatalogName": newName,
				"path":              srcObj.GetPath(),
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
			}
			pathname = "/orchestration/group-rebuild/catalog/v1.0/modifyGroupCatalog"
		} else {
			data = base.Json{
				"groupID":     d.CloudID,
				"contentID":   srcObj.GetID(),
				"contentName": newName,
				"path":        srcObj.GetPath(),
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
			}
			pathname = "/orchestration/group-rebuild/content/v1.0/modifyGroupContent"
		}
		_, err = d.post(pathname, data, nil)
	case MetaFamily:
		var data base.Json
		var pathname string
		if srcObj.IsDir() {
			pathname = "/modifyCloudDocV2"
			data = base.Json{
				"catalogType": 3,
				"cloudID":     d.CloudID,
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": "1",
				},
				"docLibName":   newName,
				"docLibraryID": srcObj.GetID(),
				"path":         path.Join(srcObj.GetPath(), srcObj.GetID()),
			}
			var resp ModifyCloudDocV2Resp
			_, err = d.andAlbumRequest(pathname, data, &resp)
			if err != nil {
				return err
			}
			if resp.Result.ResultCode != "0" {
				return fmt.Errorf("failed to rename family folder: %s", resp.Result.ResultDesc)
			}
			return nil
		} else {
			data = base.Json{
				"contentID":   srcObj.GetID(),
				"contentName": newName,
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
				"path": srcObj.GetPath(),
			}
			pathname = "/orchestration/familyCloud-rebuild/photoContent/v1.0/modifyContentInfo"
		}
		_, err = d.post(pathname, data, nil)
	default:
		err = errs.NotImplement
	}
	return err
}

func (d *Yun139) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	var err error
	switch d.Addition.Type {
	case MetaPersonalNew:
		data := base.Json{
			"fileIds":        []string{srcObj.GetID()},
			"toParentFileId": dstDir.GetID(),
		}
		pathname := "/file/batchCopy"
		_, err := d.personalPost(pathname, data, nil)
		return err
	case MetaPersonal:
		var contentInfoList []string
		var catalogInfoList []string
		if srcObj.IsDir() {
			catalogInfoList = append(catalogInfoList, srcObj.GetID())
		} else {
			contentInfoList = append(contentInfoList, srcObj.GetID())
		}
		data := base.Json{
			"createBatchOprTaskReq": base.Json{
				"taskType":   3,
				"actionType": 309,
				"taskInfo": base.Json{
					"contentInfoList": contentInfoList,
					"catalogInfoList": catalogInfoList,
					"newCatalogID":    dstDir.GetID(),
				},
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
			},
		}
		pathname := "/orchestration/personalCloud/batchOprTask/v1.0/createBatchOprTask"
		_, err = d.post(pathname, data, nil)
	case MetaGroup:
		err = d.handleMetaGroupCopy(ctx, srcObj, dstDir)
	case MetaFamily:
		pathname := "/copyContentCatalog"
		var sourceContentIDs []string
		var sourceCatalogIDs []string
		if srcObj.IsDir() {
			sourceCatalogIDs = append(sourceCatalogIDs, srcObj.GetID())
		} else {
			sourceContentIDs = append(sourceContentIDs, srcObj.GetID())
		}

		body := base.Json{
			"commonAccountInfo": base.Json{
				"accountType":   "1",
				"accountUserId": d.ref.UserDomainID,
			},
			"destCatalogID":    dstDir.GetID(),
			"destCloudID":      d.CloudID,
			"sourceCatalogIDs": sourceCatalogIDs,
			"sourceCloudID":    d.CloudID,
			"sourceContentIDs": sourceContentIDs,
		}

		var resp base.Json // Assuming a generic JSON response for success/failure
		_, err = d.andAlbumRequest(pathname, body, &resp)
		// For now, we assume no error means success.
	default:
		return errs.NotImplement
	}
	return err
}

func (d *Yun139) Remove(ctx context.Context, obj model.Obj) error {
	switch d.Addition.Type {
	case MetaPersonalNew:
		data := base.Json{
			"fileIds": []string{obj.GetID()},
		}
		pathname := "/recyclebin/batchTrash"
		_, err := d.personalPost(pathname, data, nil)
		return err
	case MetaGroup:
		var contentList []string
		var catalogList []string
		// 必须使用完整路径删除
		if obj.IsDir() {
			catalogList = append(catalogList, obj.GetPath())
		} else {
			contentList = append(contentList, path.Join(obj.GetPath(), obj.GetID()))
		}
		data := base.Json{
			"taskType":    2,
			"srcGroupID":  d.CloudID,
			"contentList": contentList,
			"catalogList": catalogList,
			"commonAccountInfo": base.Json{
				"account":     d.getAccount(),
				"accountType": 1,
			},
		}
		pathname := "/orchestration/group-rebuild/task/v1.0/createBatchOprTask"
		_, err := d.post(pathname, data, nil)
		return err
	case MetaPersonal:
		fallthrough
	case MetaGroup: // 修复原版无MetaGroup处理落入default的隐藏风险
		fallthrough
	case MetaFamily:
		var contentInfoList []string
		var catalogInfoList []string
		if obj.IsDir() {
			catalogInfoList = append(catalogInfoList, obj.GetID())
		} else {
			contentInfoList = append(contentInfoList, obj.GetID())
		}
		data := base.Json{
			"createBatchOprTaskReq": base.Json{
				"taskType":   2,
				"actionType": 201,
				"taskInfo": base.Json{
					"newCatalogID":    "",
					"contentInfoList": contentInfoList,
					"catalogInfoList": catalogInfoList,
				},
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
			},
		}
		pathname := "/orchestration/personalCloud/batchOprTask/v1.0/createBatchOprTask"
		if d.isFamily() {
			data = base.Json{
				"catalogList": catalogInfoList,
				"contentList": contentInfoList,
				"commonAccountInfo": base.Json{
					"account":     d.getAccount(),
					"accountType": 1,
				},
				"sourceCloudID":     d.CloudID,
				"sourceCatalogType": 1002,
				"taskType":          2,
				"path":              obj.GetPath(),
			}
			pathname = "/orchestration/familyCloud-rebuild/batchOprTask/v1.0/createBatchOprTask"
		}
		_, err := d.post(pathname, data, nil)
		return err
	default:
		return errs.NotImplement
	}
}

func (d *Yun139) getPartSize(size int64) int64 {
	if d.CustomUploadPartSize != 0 {
		return d.CustomUploadPartSize
	}
	// 网盘对于分片数量存在上限
	if size/utils.GB > 30 {
		return 512 * utils.MB
	}
	return 100 * utils.MB
}

func (d *Yun139) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) error {
	switch d.Addition.Type {
	case MetaPersonalNew:
		var err error
		fullHash := stream.GetHash().GetHash(utils.SHA256)
		if len(fullHash) != utils.SHA256.Width {
			// 【上一轮重大修改】：如果可以断定为本地物理文件流，使用 io.Seeker 绕过笨重的 CacheFile 读写拉锯战
			if seeker, ok := stream.(io.Seeker); ok {
				log.Infof("[139] Detected local file stream. Calculating purely in-memory SHA256 for: %s", stream.GetName())
				h := sha256.New()
				
				// 分配 8MB 超大缓冲区，保护机械硬盘，使顺序读取速度拉满至硬件极限
				buf := make([]byte, 8*1024*1024)
				pHash := driver.NewProgress(stream.GetSize(), up)
				r := io.TeeReader(stream, pHash)

				_, err = io.CopyBuffer(h, r, buf)
				if err != nil {
					return err
				}
				
				// 核心对齐：移动云盘标准哈希检验强制要求 64 位纯大写字母串
				fullHash = strings.ToUpper(hex.EncodeToString(h.Sum(nil))

				// 【倒带机制】：哈希计算完毕后，立刻将文件物理指针重置回到开头(0)，供接下来的硬上传平滑读取
				_, err = seeker.Seek(0, io.SeekStart)
				if err != nil {
					return err
				}
			} else {
				// 兜底策略：如果非物理可倒带流（如远程拉取的流），走标准库缓存机制，并修复原版丢弃流的bug
				log.Warnf("[139] Stream is not seekable, fallback to CacheFullAndHash")
				var newStream model.FileStreamer
				newStream, fullHash, err = streamPkg.CacheFullAndHash(stream, &up, utils.SHA256)
				if err != nil {
					return err
				}
				stream = newStream
				fullHash = strings.ToUpper(fullHash)
			}
		}

		size := stream.GetSize()
		partSize := d.getPartSize(size)
		part := int64(1)
		if size > partSize {
			part = (size + partSize - 1) / partSize
		}

		// 生成所有 partInfos
		partInfos := make([]PartInfo, 0, part)
		for i := int64(0); i < part; i++ {
			if utils.IsCanceled(ctx) {
				return ctx.Err()
			}
			start := i * partSize
			byteSize := min(size-start, partSize)
			partNumber := i + 1
			partInfo := PartInfo{
				PartNumber: partNumber,
				PartSize:   byteSize,
				ParallelHashCtx: ParallelHashCtx{
					PartOffset: start,
				},
			}
			partInfos = append(partInfos, partInfo)
		}

		// 筛选出前 100 个 partInfos
		firstPartInfos := partInfos
		if len(firstPartInfos) > 100 {
			firstPartInfos = firstPartInfos[:100]
		}

		// 【本轮核心修复点】：剔除引发“00010002请求参数不合法”的所有高危秒传预检马甲字段，还原安全干净的 Payload 结构
		data := base.Json{
			"contentHash":          fullHash,
			"contentHashAlgorithm": "SHA256",
			"contentType":          "application/octet-stream",
			"parallelUpload":       false, // 完全关闭强行并发通道，走上一版安全链路
			"partInfos":            firstPartInfos,
			"size":                 size,
			"parentFileId":         dstDir.GetID(),
			"name":                 stream.GetName(),
			"type":                 "file",
			"fileRenameMode":       "auto_rename",
		}
		pathname := "/file/create"
		var resp PersonalUploadResp
		_, err = d.personalPost(pathname, data, &resp)
		if err != nil {
			return err
		}

		// 判断文件是否已存在
		if resp.Data.Exist {
			return nil
		}

		if resp.Data.PartInfos != nil {
			// Progress
			p := driver.NewProgress(size, up)
			rateLimited := driver.NewLimitedUploadStream(ctx, stream)

			// 先上传前100个分片
			err = d.uploadPersonalParts(ctx, partInfos, resp.Data.PartInfos, rateLimited, p)
			if err != nil {
				return err
			}

			// 如果还有剩余分片，分批获取上传地址并上传
			for i := 100; i < len(partInfos); i += 100 {
				end := min(i+100, len(partInfos))
				batchPartInfos := partInfos[i:end]
				moredata := base.Json{
					"fileId":    resp.Data.FileId,
					"uploadId":  resp.Data.UploadId,
					"partInfos": batchPartInfos,
					"commonAccountInfo": base.Json{
						"account":     d.getAccount(),
						"accountType": 1,
					},
				}
				pathname := "/file/getUploadUrl"
				var moreresp PersonalUploadUrlResp
				_, err = d.personalPost(pathname, moredata, &moreresp)
				if err != nil {
					return err
				}
				err = d.uploadPersonalParts(ctx, partInfos, moreresp.Data.PartInfos, rateLimited, p)
				if err != nil {
					return err
				}
			}

			// 全部分片上传完毕后，complete
			data = base.Json{
				"contentHash":          fullHash,
				"contentHashAlgorithm": "SHA256",
				"fileId":               resp.Data.FileId,
				"uploadId":             resp.Data.UploadId,
			}
			_, err = d.personalPost("/file/complete", data, nil)
			if err != nil {
				return err
			}
		}

		// 处理冲突
		if resp.Data.FileName != stream.GetName() {
			log.Debugf("[139] conflict detected: %s != %s", resp.Data.FileName, stream.GetName())
			time.Sleep(time.Millisecond * 500)
			files, err := d.List(ctx, dstDir, model.ListArgs{Refresh: true})
			if err != nil {
				return err
			}
			for _, file := range files {
				if file.GetName() == stream.GetName() {
					log.Debugf("[139] conflict: removing old: %s", file.GetName())
					err = d.Rename(ctx, file, stream.GetName()+random.String(4))
					if err != nil {
						return err
					}
					err = d.Remove(ctx, file)
					if err != nil {
						return err
					}
					break
				}
			}
			for _, file := range files {
				if file.GetName() == resp.Data.FileName {
					log.Debugf("[139] conflict: renaming new: %s => %s", file.GetName(), stream.GetName())
					err = d.Rename(ctx, file, stream.GetName())
					if err != nil {
						return err
					}
					break
				}
			}
		}
		return nil

	case MetaPersonal:
		fallthrough
	case MetaGroup:
		fallthrough
	case MetaFamily:
		// 获取文件列表处理冲突
		files, err := d.List(ctx, dstDir, model.ListArgs{})
		if err != nil {
			return err
		}
		for _, file := range files {
			if file.GetName() == stream.GetName() {
				log.Debugf("[139] conflict: removing old: %s", file.GetName())
				err = d.Rename(ctx, file, stream.GetName()+random.String(4))
				if err != nil {
					return err
				}
				err = d.Remove(ctx, file)
				if err != nil {
					return err
				}
				break
			}
		}
		var reportSize int64
		if d.ReportRealSize {
			reportSize = stream.GetSize()
		} else {
			reportSize = 0
		}
		data := base.Json{
			"manualRename": 2,
			"operation":    0,
			"fileCount":    1,
			"totalSize":    reportSize,
			"uploadContentList": []base.Json{{
				"contentName": stream.GetName(),
				"contentSize": reportSize,
			}},
			"parentCatalogID": dstDir.GetID(),
			"newCatalogName":  "",
			"commonAccountInfo": base.Json{
				"account":     d.getAccount(),
				"accountType": 1,
			},
		}
		pathname := "/orchestration/personalCloud/uploadAndDownload/v1.0/pcUploadFileRequest"
		if d.isFamily() || d.Addition.Type == MetaGroup {
			uploadPath := path.Join(dstDir.GetPath(), dstDir.GetID())
			if dstDir.GetID() == d.RootFolderID {
				uploadPath = d.RootPath
			}
			data = d.newJson(base.Json{
				"fileCount":    1,
				"manualRename": 2,
				"operation":    0,
				"path":         uploadPath,
				"seqNo":        random.String(32),
				"totalSize":    reportSize,
				"uploadContentList": []base.Json{{
					"contentName": stream.GetName(),
					"contentSize": reportSize,
				}},
			})
			pathname = "/orchestration/familyCloud-rebuild/content/v1.0/getFileUploadURL"
		}
		var resp UploadResp
		log.Debugf("[139] upload request body: %+v", data)
		_, err = d.post(pathname, data, &resp)
		if err != nil {
			return err
		}
		if resp.Data.Result.ResultCode != "0" {
			return fmt.Errorf("get file upload url failed with result code: %s, message: %s", resp.Data.Result.ResultCode, resp.Data.Result.ResultDesc)
		}

		size := stream.GetSize()
		p := driver.NewProgress(size, up)
		partSize := d.getPartSize(size)
		part := int64(1)
		if size > partSize {
			part = (size + partSize - 1) / partSize
		}
		rateLimited := driver.NewLimitedUploadStream(ctx, stream)
		for i := int64(0); i < part; i++ {
			if utils.IsCanceled(ctx) {
				return ctx.Err()
			}

			start := i * partSize
			byteSize := min(size-start, partSize)

			limitReader := io.LimitReader(rateLimited, byteSize)
			r := io.TeeReader(limitReader, p)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, resp.Data.UploadResult.RedirectionURL, r)
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "text/plain;name="+unicode(stream.GetName()))
			req.Header.Set("contentSize", strconv.FormatInt(size, 10))
			req.Header.Set("range", fmt.Sprintf("bytes=%d-%d", start, start+byteSize-1))
			req.Header.Set("uploadtaskID", resp.Data.UploadResult.UploadTaskID)
			req.Header.Set("rangeType", "0")
			req.ContentLength = byteSize

			res, err := base.HttpClient.Do(req)
			if err != nil {
				return err
			}
			if res.StatusCode != http.StatusOK {
				res.Body.Close()
				return fmt.Errorf("unexpected status code: %d", res.StatusCode)
			}
			bodyBytes, err := io.ReadAll(res.Body)
			if err != nil {
				return fmt.Errorf("error reading response body: %v", err)
			}
			var result InterLayerUploadResult
			err = xml.Unmarshal(bodyBytes, &result)
			if err != nil {
				return fmt.Errorf("error parsing XML: %v", err)
			}
			if result.ResultCode != 0 {
				return fmt.Errorf("upload failed with result code: %d, message: %s", result.ResultCode, result.Msg)
			}
		}
		return nil
	default:
		return errs.NotImplement
	}
}

func (d *Yun139) Other(ctx context.Context, args model.OtherArgs) (interface{}, error) {
	switch d.Addition.Type {
	case MetaPersonalNew:
		var resp base.Json
		var uri string
		data := base.Json{
			"category": "video",
			"fileId":   args.Obj.GetID(),
		}
		switch args.Method {
		case "video_preview":
			uri = "/videoPreview/getPreviewInfo"
		default:
			return nil, errs.NotSupport
		}
		_, err := d.personalPost(uri, data, &resp)
		if err != nil {
			return nil, err
		}
		return resp["data"], nil
	default:
		return nil, errs.NotImplement
	}
}

func (d *Yun139) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	if d.UserDomainID == "" {
		return nil, errs.NotImplement
	}
	var total, used int64
	if d.isFamily() {
		diskInfo, err := d.getFamilyDiskInfo(ctx)
		if err != nil {
			return nil, err
		}
		totalMb, err := strconv.ParseInt(diskInfo.Data.DiskSize, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed convert disk size into integer: %+v", err)
		}
		usedMb, err := strconv.ParseInt(diskInfo.Data.UsedSize, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed convert used size into integer: %+v", err)
		}
		total = totalMb * 1024 * 1024
		used = usedMb * 1024 * 1024
	} else {
		diskInfo, err := d.getPersonalDiskInfo(ctx)
		if err != nil {
			return nil, err
		}
		totalMb, err := strconv.ParseInt(diskInfo.Data.DiskSize, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed convert disk size into integer: %+v", err)
		}
		freeMb, err := strconv.ParseInt(diskInfo.Data.FreeDiskSize, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed convert free size into integer: %+v", err)
		}
		total = totalMb * 1024 * 1024
		used = total - (freeMb * 1024 * 1024)
	}
	return &model.StorageDetails{
		DiskUsage: model.DiskUsage{
			TotalSpace: total,
			UsedSpace:  used,
		},
	}, nil
}

var _ driver.Driver = (*Yun139)(nil)
