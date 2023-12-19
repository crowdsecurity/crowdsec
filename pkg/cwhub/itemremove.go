package cwhub

import (
	"fmt"
	"os"

	"slices"
)

// purge removes the actual config file that was downloaded.
func (i *Item) purge() (bool, error) {
	if !i.State.Downloaded {
		i.hub.logger.Debugf("removing %s: not downloaded -- no need to remove", i.Name)
		return false, nil
	}

	src, err := i.downloadPath()
	if err != nil {
		return false, err
	}

	if err := os.Remove(src); err != nil {
		if os.IsNotExist(err) {
			i.hub.logger.Debugf("%s doesn't exist, no need to remove", src)
			return false, nil
		}

		return false, fmt.Errorf("while removing file: %w", err)
	}

	i.State.Downloaded = false
	i.hub.logger.Infof("Removed source file [%s]: %s", i.Name, src)

	return true, nil
}

// disable removes the install link, and optionally the downloaded content.
func (i *Item) disable(purge bool, force bool) (bool, error) {
	didRemove := true

	err := i.removeInstallLink()
	if os.IsNotExist(err) {
		if !purge && !force {
			link, _ := i.installPath()
			return false, fmt.Errorf("link %s does not exist (override with --force or --purge)", link)
		}

		didRemove = false
	} else if err != nil {
		return false, err
	}

	i.State.Installed = false
	didPurge := false

	if purge {
		if didPurge, err = i.purge(); err != nil {
			return didRemove, err
		}
	}

	ret := didRemove || didPurge

	return ret, nil
}

// Remove disables the item, optionally removing the downloaded content.
func (i *Item) Remove(purge bool, force bool) (bool, error) {
	if i.State.IsLocal() {
		i.hub.logger.Warningf("%s is a local item, please delete manually", i.Name)
		return false, nil
	}

	if i.State.Tainted && !force {
		return false, fmt.Errorf("%s is tainted, use '--force' to remove", i.Name)
	}

	if !i.State.Installed && !purge {
		i.hub.logger.Infof("removing %s: not installed -- no need to remove", i.Name)
		return false, nil
	}

	removed := false

	descendants, err := i.descendants()
	if err != nil {
		return false, err
	}

	ancestors := i.Ancestors()

	for _, sub := range i.SubItems() {
		if !sub.State.Installed {
			continue
		}

		// if the sub depends on a collection that is not a direct or indirect dependency
		// of the current item, it is not removed
		for _, subParent := range sub.Ancestors() {
			if !purge && !subParent.State.Installed {
				continue
			}

			// the ancestor that would block the removal of the sub item is also an ancestor
			// of the item we are removing, so we don't want false warnings
			// (e.g. crowdsecurity/sshd-logs was not removed because it also belongs to crowdsecurity/linux,
			// while we are removing crowdsecurity/sshd)
			if slices.Contains(ancestors, subParent) {
				continue
			}

			// the sub-item belongs to the item we are removing, but we already knew that
			if subParent == i {
				continue
			}

			if !slices.Contains(descendants, subParent) {
				i.hub.logger.Infof("%s was not removed because it also belongs to %s", sub.Name, subParent.Name)
				continue
			}
		}

		subRemoved, err := sub.Remove(purge, force)
		if err != nil {
			return false, fmt.Errorf("unable to disable %s: %w", i.Name, err)
		}

		removed = removed || subRemoved
	}

	didDisable, err := i.disable(purge, force)
	if err != nil {
		return false, fmt.Errorf("while removing %s: %w", i.Name, err)
	}

	removed = removed || didDisable

	return removed, nil
}
