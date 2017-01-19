package amipublisher

import (
	"github.com/Symantec/Dominator/lib/awsutil"
	"github.com/Symantec/Dominator/lib/filesystem"
	"github.com/Symantec/Dominator/lib/log"
	"time"
)

type publishData struct {
	imageServerAddress string
	streamName         string
	imageLeafName      string
	minFreeBytes       uint64
	amiName            string
	tags               map[string]string
	unpackerName       string
	// Computed data follow.
	fileSystem *filesystem.FileSystem
}

type Resource struct {
	awsutil.Target
	SnapshotId string
	AmiId      string
}

type Results []TargetResult

type TargetResult struct {
	awsutil.Target
	SnapshotId string
	AmiId      string
	Size       uint // Size in GiB.
	Error      error
}

type TargetUnpackers struct {
	awsutil.Target
	Unpackers []Unpacker
}

type Unpacker struct {
	InstanceId        string
	IpAddress         string
	State             string
	TimeSinceLastUsed string `json:",omitempty"`
}

func (v TargetResult) MarshalJSON() ([]byte, error) {
	return v.marshalJSON()
}

func DeleteResources(resources []Resource, logger log.Logger) error {
	return deleteResources(resources, logger)
}

func DeleteTags(resources []Resource, tagKeys []string,
	logger log.Logger) error {
	return deleteTags(resources, tagKeys, logger)
}

func ExpireResources(targets awsutil.TargetList, skipList awsutil.TargetList,
	logger log.Logger) error {
	return expireResources(targets, skipList, logger)
}

func ListUnpackers(targets awsutil.TargetList, skipList awsutil.TargetList,
	name string, logger log.Logger) (
	[]TargetUnpackers, error) {
	return listUnpackers(targets, skipList, name, logger)
}

func PrepareUnpackers(streamName string, targets awsutil.TargetList,
	skipList awsutil.TargetList, name string, logger log.Logger) error {
	return prepareUnpackers(streamName, targets, skipList, name, logger)
}

func Publish(imageServerAddress string, streamName string, imageLeafName string,
	minFreeBytes uint64, amiName string, tags map[string]string,
	targets awsutil.TargetList, skipList awsutil.TargetList,
	unpackerName string, logger log.Logger) (
	Results, error) {
	pData := &publishData{
		imageServerAddress: imageServerAddress,
		streamName:         streamName,
		imageLeafName:      imageLeafName,
		minFreeBytes:       minFreeBytes,
		amiName:            amiName,
		tags:               tags,
		unpackerName:       unpackerName,
	}
	return pData.publish(targets, skipList, logger)
}

func SetExclusiveTags(resources []Resource, tagKey string, tagValue string,
	logger log.Logger) error {
	return setExclusiveTags(resources, tagKey, tagValue, logger)
}

func StopIdleUnpackers(targets awsutil.TargetList, skipList awsutil.TargetList,
	name string, idleTimeout time.Duration, logger log.Logger) error {
	return stopIdleUnpackers(targets, skipList, name, idleTimeout, logger)
}