<?php
/*
 Plugin Name: WPRakia FILESAFE Lite
 Plugin URI: https://github.com/wprakia/filesafe
 Description: Stop bad files where WP fails :)
 Author: Slavco Mihajloski
 Version: 1.0
 Author URI: https://medium.com/websec
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

//do not change this values except you know what are you doing :)
if ( !defined("WPRAKIA_FILESAFE_CHUNKSIZE")  ) define("WPRAKIA_FILESAFE_CHUNKSIZE", 1000);
if ( !defined("WPRAKIA_FILESAFE_MOVEBACK")  )  define("WPRAKIA_FILESAFE_MOVEBACK",  100);
if ( !defined("WPRAKIA_FILESAFE_FILESTART")  ) define("WPRAKIA_FILESAFE_FILESTART", 0);

function wp_rakia_filesafe_exotic_types(){
    
    $exotic_types = array(
        "image/",
        "audio/",
        "video/",
        "text/"
    );
    
    return apply_filters("wp_rakia_filesafe_exotic_types", $exotic_types);
    
}


function wp_rakia_filesafe_bad_formats(){
    
    $bad_format_start = array(
        "FWS",
        "CWS",
        "ZWS",
        "%!PS",
        "%PDF"
    );
    
    return apply_filters("wp_rakia_filesafe_bad_formats", $bad_format_start); 

}

function wp_rakia_filesafe_bad_content(){
    
    $bad_content = array(
        "<?php",
        "<?="
    );
    
    return apply_filters("wp_rakia_filesafe_bad_content", $bad_content);

}

function wp_rakia_filesafe_action_upload_bits($input_array){
    
    if ( is_array($input_array) && isset($input_array["name"]) && isset($input_array["bits"]) && strlen($input_array["bits"]) > 0){

        $wprakia_sf = new WPRAKIA_ScanFile();
        $wprakia_sf->createTmpFile($input_array["bits"]);
        
        $start_check = TRUE;
        $content_check = TRUE;
        
        if ( $wprakia_sf->open() ){
            
            $wp_file_t = wp_check_filetype($input_array["name"]);
            $wp_file_type = strtolower($wp_file_t["type"]);
            
            $go_for_start = false;
            $exotic_types = wp_rakia_filesafe_exotic_types();
            
            if ( is_array($exotic_types) ){
                
                foreach($exotic_types as $etype){
                    
                    if ( strpos($wp_file_type, $etype) === 0 ){
                        
                        $go_for_start = true;
                        break;
                    
                    }
                
                }
            
            }
            
            if( $go_for_start ){
                
                $start_check = apply_filters("wp_rakia_filesafe_check_start", $wprakia_sf->checkStart(wp_rakia_filesafe_bad_formats()), $wprakia_sf->file_path);
            
            }
            
            $content_check = apply_filters("wp_rakia_filesafe_check_content", $wprakia_sf->checkContent(wp_rakia_filesafe_bad_content()), $wprakia_sf->file_path);
            
        }
        
        if ( $start_check )   apply_filters("wp_rakia_filesafe_log_start", __( 'Sorry, this file type is not permitted for security reasons.' ), $input_array["name"], $wprakia_sf->file_path, $start_check);
        if ( $content_check ) apply_filters("wp_rakia_filesafe_log_content", __( 'Sorry, this file type is not permitted for security reasons.' ), $input_array["name"], $wprakia_sf->file_path, $content_check);
        
        $wprakia_sf->close();
        
        if ( $start_check === FALSE && $content_check === FALSE ){
            
            return $input_array;
        
        }else{
        
            return __( 'Sorry, this file type is not permitted for security reasons.' );
            
        }
    
    }else{
    
        return FALSE;
    
    }
}

add_action("wp_upload_bits", "wp_rakia_filesafe_action_upload_bits", 1, 1);


function wp_rakia_filesafe_action_upload($out, $file, $new_file, $type){
    
    if ( !is_null($out) ) return $out;
    
    $wprakia_sf = new WPRAKIA_ScanFile();
    
    $start_check = TRUE;
    $content_check = TRUE;
    
    if ( is_array($file) && isset($file["tmp_name"]) && $wprakia_sf->open($file["tmp_name"]) ){
        
        $wp_file_type = strtolower($type);
        
        $go_for_start = false;
        $exotic_types = wp_rakia_filesafe_exotic_types();
        
        if ( is_array($exotic_types) ){
            
            foreach($exotic_types as $etype){
                
                if ( strpos($wp_file_type, $etype) === 0 ){
                    
                    $go_for_start = true;
                    break;
                    
                }
                
            }
            
        }
        
        if( $go_for_start ){
            
            $start_check = apply_filters("wp_rakia_filesafe_check_start", $wprakia_sf->checkStart(wp_rakia_filesafe_bad_formats()), $wprakia_sf->file_path);
            
        }
        
        $content_check = apply_filters("wp_rakia_filesafe_check_content", $wprakia_sf->checkContent(wp_rakia_filesafe_bad_content()), $wprakia_sf->file_path);
        
        if ( $start_check )   apply_filters("wp_rakia_filesafe_log_start", __( 'Sorry, this file type is not permitted for security reasons.' ), $file['name'], $wprakia_sf->file_path, $start_check);
        if ( $content_check ) apply_filters("wp_rakia_filesafe_log_content", __( 'Sorry, this file type is not permitted for security reasons.' ), $file['name'], $wprakia_sf->file_path, $content_check);
        
        $wprakia_sf->close();
    
    }
    
    if ( $start_check || $content_check ) { 
    
        return TRUE; 
    
    }else{ 
        
        return null; 
    
    }

}

add_action("pre_move_uploaded_file", "wp_rakia_filesafe_action_upload", 1, 4);

function wp_rakia_filesafe_check_file_exists($in_array, $action){
    
    if ( !is_array($in_array) || !isset($in_array["file"]) || !@file_exists($in_array["file"]) ){
        
        $in_array["error"] = __( 'Sorry, this file type is not permitted for security reasons.' );
    
    }
    
    return $in_array;
    
}

add_action("wp_handle_upload","wp_rakia_filesafe_check_file_exists", 1, 2);


function wp_rakia_filesafe_action_image_crop($file = "", $id = 0){
    
    $wprakia_sf = new WPRAKIA_ScanFile();
    
    $start_check = TRUE;
    $content_check = TRUE;
    
    if ( $file && $wprakia_sf->open($file) ){
        
        $wp_file_t = wp_check_filetype($file);
        $wp_file_type = strtolower($wp_file_t["type"]);
        
        $go_for_start = false;
        $exotic_types = wp_rakia_filesafe_exotic_types();
        
        if ( is_array($exotic_types) ){
            
            foreach($exotic_types as $etype){
                
                if ( strpos($wp_file_type, $etype) === 0 ){
                    
                    $go_for_start = true;
                    break;
                    
                }
                
            }
            
        }
        
        if( $go_for_start ){
            
            $start_check = apply_filters("wp_rakia_filesafe_check_start", $wprakia_sf->checkStart(wp_rakia_filesafe_bad_formats()), $wprakia_sf->file_path);
            
        }
        
        $content_check = apply_filters("wp_rakia_filesafe_check_content", $wprakia_sf->checkContent(wp_rakia_filesafe_bad_content()), $wprakia_sf->file_path);
        
        if ( $start_check )   apply_filters("wp_rakia_filesafe_log_start", __( 'Sorry, this file type is not permitted for security reasons.' ), $file, $wprakia_sf->file_path, $start_check);
        if ( $content_check ) apply_filters("wp_rakia_filesafe_log_content", __( 'Sorry, this file type is not permitted for security reasons.' ), $file, $wprakia_sf->file_path, $content_check);
        
        $wprakia_sf->close();
        
        if ( $start_check === FALSE && $content_check === FALSE ){
            
            return $file;
            
        }else{
            
            wp_delete_file($file);
            
            if ( is_numeric($id) ) wp_delete_attachment($id, true);
            
            return FALSE;
            
        }
        
    }

}

//race condition isn't handled, but hey, it is WP...
add_action("wp_create_file_in_uploads", "wp_rakia_filesafe_action_image_crop", 1, 2);


class WPRAKIA_ScanFile{

    function __construct($file_path = ""){
        
        $this->file_path = $file_path;
        $this->isTmp = FALSE;
    
    }
    
    function createTmpFile($in_bits=""){
        
        if ( strlen($in_bits) > 0 ){
            
            $tmpfname = tempnam(get_temp_dir(), 'WPRAKIA');
            
            if ( $tmpfname !== FALSE ){
            
                $this->file_path = $tmpfname;
                $this->isTmp = TRUE;
                @file_put_contents($this->file_path, $in_bits);
                return TRUE;
            
            }else{
                
                return FALSE;
            
            }
        
        }else{
            
            return FALSE;
        
        }
    
    }
    
    function open($file_path = ""){
        
        if ( $file_path ){
            
            $this->file_path = $file_path;
        
        }
        
        if ( file_exists($this->file_path) ){
            
            return $this->fh = @fopen($this->file_path, "rb");
        
        }else{
            
            return FALSE;
        
        }
    
    }
    
    function close(){
        
        if ( is_resource($this->fh) ) fclose($this->fh);
        if ( $this->isTmp && strpos($this->file_path, get_temp_dir().basename($this->file_path)) === 0 ) @unlink($this->file_path);
        
        $this->file_path = "";
        $this->isTmp = FALSE;
    
    }
    
    function checkStart( $in_constraints = array(), $position = 0 ){
        
        $out = array();
        
        if ( $this->fh && is_resource( $this->fh ) ){
            
            fseek($this->fh, WPRAKIA_FILESAFE_FILESTART);
            $tmp = fread($this->fh, WPRAKIA_FILESAFE_CHUNKSIZE);
            
            if ( $tmp && is_array($in_constraints) && sizeof($in_constraints) > 0 ){
                
                foreach ($in_constraints as $key=>$constraint){
                    
                    if ( strpos($tmp, $constraint) === WPRAKIA_FILESAFE_FILESTART ){
                        
                        $out[] = $constraint; 
                    
                    }
                
                }
                
                $tmp = "";
            
            }
        
        }
        if ( sizeof($out) > 0 ){
            
            return $out;
        
        }else{
            
            return FALSE;
        
        }
    
    }
    
    function checkContent( $in_constraints = array() ){
        
        $out = array();
        
        if ( $this->fh && is_resource( $this->fh ) ){
            
            fseek($this->fh, WPRAKIA_FILESAFE_FILESTART);
            $current = WPRAKIA_FILESAFE_FILESTART;
            
            while (! feof($this->fh) ){
                
                $tmp = fread($this->fh, WPRAKIA_FILESAFE_CHUNKSIZE);
                
                if ( $tmp && is_array($in_constraints) && sizeof($in_constraints) > 0 ){
                    
                    foreach ($in_constraints as $key=>$constraint){
                        
                        if ( ($lc = strpos($tmp, $constraint)) !== FALSE ){
                            
                            $out[$current + $lc] = $constraint;    
                        
                        }
                    
                    }
                
                }
                
                if ( ! feof($this->fh) ){
                    
                    $current = ftell($this->fh);
                    
                    if ( is_numeric($current) && $current > 0 && $current > WPRAKIA_FILESAFE_MOVEBACK ){
                        
                        $current = $current - WPRAKIA_FILESAFE_MOVEBACK;
                        fseek($this->fh, $current);
                    
                    }
                
                }
            
            }
            
            if ( sizeof($out) > 0 ) return $out;
        
        }
        
        return FALSE;
    
    }

}

?>
