<?php

require_once ABSPATH . WPINC . '/class-wp-image-editor.php';
require_once ABSPATH . WPINC . '/class-wp-image-editor-gd.php';
require_once ABSPATH . WPINC . '/class-wp-image-editor-imagick.php';

class wfImage {
	
	private $driver;
	
	public function __construct($driver = null) {
		if ($driver !== null) {
			$this->driver = $driver;
		} else {
			$this->autoSelectDriver();
		}
	}
	
	public function autoSelectDriver() {
		if (WP_Image_Editor_GD::test()) {
			$this->setDriver(new wfImageDriverGD);
			
		} elseif (WP_Image_Editor_Imagick::test()) {
			$this->setDriver(new wfImageDriverImagick);
		}
	}
	
	public function __call($method, $args) {
		if (!$this->getDriver()) {
			throw new wfImageException("No driver has been set for wfImage, or no suitable driver was found.");
		}
		
		return call_user_func_array(array(
			$this->getDriver(),
			$method,
		), $args);
	}
	
	public function setDriver($driver) {
		$this->driver = $driver;
	}
	
	public function getDriver() {
		return $this->driver;
	}
}


class wfImageDriverGD extends wfImageDriverBase {
	
	private $image;
	public $jpeg_quality = 80;
	
	public function newImage($width, $height) {
		$this->image = imagecreatetruecolor($height, $width);
		return $this;
	}
	
	public function drawText($text) {
		// TODO: calculate width/height based on font
		if ($this->image === null) {
			$this->newImage(16, strlen($text) * ($this->getFont() + 4));
		}

		$bg_color = $this->hex2rgb($this->getBackgroundColor());
		$background_color = imagecolorallocate($this->image, $bg_color['r'], $bg_color['g'], $bg_color['b']);
		imagefill($this->image, 0, 0, $background_color);
		
		$text_color = $this->hex2rgb($this->getTextColor());
		$text_color_resource = imagecolorallocate($this->image, $text_color['r'], $text_color['g'], $text_color['b']);

		// TODO: image padding
		imagestring($this->image, $this->getFont(), 0, 0, $text, $text_color_resource);
		
		return $this;
	}
	
	public function save($file, $type) {
		if ($this->image === null) {
			throw new wfImageException("Image has not been created.  Call newImage before calling save.");
		}
		
		if (is_string($type)) {
			$type = strtolower($type);
		}
		
		switch ($type) {
			case IMAGETYPE_PNG:
			case 'png':
				imagepng($this->image, $file);
				break;
			
			case IMAGETYPE_GIF:
			case 'gif':
				imagegif($this->image, $file);
				break;
			
			case IMAGETYPE_JPEG:
			case 'jpg':
			default:
				imagejpeg($this->image, $file, $this->jpeg_quality);
				break;
		}
		
		return $this;
	}
	
	public function output($type = "jpg", $exit = true) {
		if ($this->image === null) {
			throw new wfImageException("Image has not been created.  Call newImage before calling output.");
		}
		
		if (is_string($type)) {
			$type = strtolower($type);
		}
		
		switch ($type) {
			case IMAGETYPE_PNG:
			case 'png':
				header('Content-type: ' . image_type_to_mime_type(IMAGETYPE_PNG));
				imagepng($this->image);
				break;
			
			case IMAGETYPE_GIF:
			case 'gif':
				header('Content-type: ' . image_type_to_mime_type(IMAGETYPE_GIF));
				imagegif($this->image);
				break;
			
			case IMAGETYPE_JPEG:
			case 'jpg':
			default:
				header('Content-type: ' . image_type_to_mime_type(IMAGETYPE_JPEG));
				imagejpeg($this->image, null, $this->jpeg_quality);
				break;
		}
		
		if ($exit) {
			exit;
		}
		
		return $this;
	}
	
	public function __destruct() {
		if ($this->image !== null && is_resource($this->image)) {
			imagedestroy($this->image);
		}
	}
}

class wfImageDriverImagick extends wfImageDriverBase {
	
	public function newImage($width, $height) {
		
	}
	
	public function drawText($text) {
		/* Create some objects */
		$image = new Imagick();
		$draw = new ImagickDraw();
		$pixel = new ImagickPixel( 'gray' );

		/* New image */
		$image->newImage(800, 75, $pixel);

		/* Black text */
		$draw->setFillColor('black');

		/* Font properties */
		$draw->setFont('Bookman-DemiItalic');
		$draw->setFontSize( 30 );

		/* Create text */
		$image->annotateImage($draw, 10, 45, 0, 'The quick brown fox jumps over the lazy dog');

		/* Give image a format */
		$image->setImageFormat('png');

		/* Output the image with headers */
		header('Content-type: image/png');
		echo $image;
	}
	
	public function output($type = "jpg", $exit = true) {
		
	}
	
	public function save($file, $type) {
		
	}
}

abstract class wfImageDriverBase {
	
	abstract public function newImage($width, $height);
	abstract public function drawText($text);
	abstract public function save($file, $type);
	abstract public function output($type = "jpg", $exit = true);
	
	protected $font = 5;
	protected $text_color = 0x000000;
	protected $background_color = 0xFFFFFF;
	
	public function getFont() {
		return $this->font;
	}
	
	public function setFont($font_file) {
		$this->font = $font_file;
		return $this;
	}
	
	public function getTextColor() {
		return $this->text_color;
	}
	
	public function setTextColor($color) {
		$this->text_color = $color;
		return $this;
	}
	
	public function getBackgroundColor() {
		return $this->background_color;
	}
	
	public function setBackgroundColor($color) {
		$this->background_color = $color;
		return $this;
	}
	
	public function hex2rgb($hex_color) {
		return array(
			'r' => $hex_color >> 16 & 0xff,
			'g' => $hex_color >> 8 & 0xff,
			'b' => $hex_color & 0xff,
		);
	}
	
}


class wfImageException extends Exception {}

